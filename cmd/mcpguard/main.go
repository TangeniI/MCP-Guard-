// Command mcpguard runs the MCP Guard gateway.
//
//	mcpguard -policy policy.yaml -upstream sample=http://127.0.0.1:9001 \
//	    -admin-listen 127.0.0.1:8081 -approver alice=<sha256 of alice's token>
//
// The agent uses http://127.0.0.1:8080/sample/mcp as its MCP endpoint and
// sends its bearer token in the Authorization header. Approvers open
// http://127.0.0.1:8081/ to decide on calls that need a human.
//
//	mcpguard audit export -db mcpguard-audit.db   # JSON Lines on stdout
//	mcpguard audit verify -db mcpguard-audit.db
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/TangeniI/MCP-Guard-/internal/approval"
	"github.com/TangeniI/MCP-Guard-/internal/audit"
	"github.com/TangeniI/MCP-Guard-/internal/guard"
	"github.com/TangeniI/MCP-Guard-/internal/policy"
	"github.com/TangeniI/MCP-Guard-/internal/proxy"
)

type upstreamFlags map[string]*url.URL

func (u upstreamFlags) String() string { return fmt.Sprint(map[string]*url.URL(u)) }

func (u upstreamFlags) Set(v string) error {
	name, raw, ok := strings.Cut(v, "=")
	if !ok {
		return errors.New("want name=url")
	}
	if _, dup := u[name]; dup {
		return fmt.Errorf("server %q given twice", name)
	}
	target, err := url.Parse(raw)
	if err != nil {
		return err
	}
	u[name] = target
	return nil
}

type approverFlags map[string]string

func (a approverFlags) String() string { return fmt.Sprintf("%d approvers", len(a)) }

func (a approverFlags) Set(v string) error {
	name, hash, ok := strings.Cut(v, "=")
	if !ok {
		return errors.New("want name=sha256")
	}
	if _, dup := a[name]; dup {
		return fmt.Errorf("approver %q given twice", name)
	}
	a[name] = hash
	return nil
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	var err error
	if len(os.Args) > 1 && os.Args[1] == "audit" {
		err = runAudit(os.Args[2:])
	} else {
		err = run(logger, os.Args[1:])
	}
	if err != nil {
		logger.Error("mcpguard failed", "err", err)
		os.Exit(1)
	}
}

func runAudit(args []string) error {
	if len(args) == 0 || (args[0] != "export" && args[0] != "verify") {
		return errors.New("usage: mcpguard audit export|verify -db FILE")
	}
	fs := flag.NewFlagSet("audit "+args[0], flag.ContinueOnError)
	dbPath := fs.String("db", "mcpguard-audit.db", "audit database file")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if _, err := os.Stat(*dbPath); err != nil {
		return fmt.Errorf("audit database: %w", err)
	}
	log, err := audit.Open(*dbPath)
	if err != nil {
		return err
	}
	defer log.Close()

	if args[0] == "export" {
		_, err = log.Export(os.Stdout)
		return err
	}
	n, err := log.Verify()
	if err != nil {
		return err
	}
	fmt.Printf("ok: %d records, chain intact\n", n)
	return nil
}

func run(logger *slog.Logger, args []string) error {
	fs := flag.NewFlagSet("mcpguard", flag.ContinueOnError)
	upstreams := upstreamFlags{}
	approvers := approverFlags{}
	listen := fs.String("listen", "127.0.0.1:8080", "address agents connect to")
	fs.Var(upstreams, "upstream", "MCP server as name=url (repeatable); served at /{name}/mcp")
	policyPath := fs.String("policy", "", "path to the policy YAML file (required unless -insecure-allow-all)")
	allowAll := fs.Bool("insecure-allow-all", false, "run with no policy and allow everything (evaluation baseline only)")
	auditPath := fs.String("audit-db", "mcpguard-audit.db", "audit database file (created if missing)")
	adminListen := fs.String("admin-listen", "", "address of the approval page; must not be reachable by agents")
	fs.Var(approvers, "approver", "person who may approve calls, as name=sha256-of-their-token (repeatable)")
	approvalTimeout := fs.Duration("approval-timeout", approval.DefaultTimeout, "how long a call waits for a human before it is refused")
	if err := fs.Parse(args); err != nil {
		return err
	}

	// Bad configuration stops startup; the gateway never runs half-configured.
	var authorizer proxy.Authorizer
	needsApproval := false
	switch {
	case *allowAll && *policyPath != "":
		return errors.New("-policy and -insecure-allow-all are mutually exclusive")
	case *allowAll:
		logger.Warn("running with NO policy: every call is allowed")
		authorizer = proxy.AllowAll{}
	case *policyPath == "":
		return errors.New("no policy: pass -policy FILE (default deny has nothing to allow without one)")
	default:
		data, err := os.ReadFile(*policyPath)
		if err != nil {
			return fmt.Errorf("reading policy: %w", err)
		}
		pol, err := policy.Parse(data)
		if err != nil {
			return err
		}
		for _, agent := range pol.Agents {
			for server, rules := range agent.Servers {
				if _, ok := upstreams[server]; !ok {
					return fmt.Errorf("policy: agent %q refers to server %q, which has no -upstream", agent.Name, server)
				}
				for _, tool := range rules.Tools {
					needsApproval = needsApproval || tool.RequiresApproval
				}
			}
		}
		logger.Info("policy loaded", "path", *policyPath, "policy_version", pol.Hash(), "agents", len(pol.Agents))
		authorizer = guard.PolicyAuthorizer{Engine: policy.NewEngine(pol)}
	}

	// Approvals: both the page address and at least one approver, or neither.
	var approver proxy.Approver
	var admin *approval.Admin
	switch {
	case *adminListen == "" && len(approvers) > 0:
		return errors.New("-approver needs -admin-listen")
	case *adminListen != "" && len(approvers) == 0:
		return errors.New("-admin-listen needs at least one -approver")
	case *adminListen != "":
		if *adminListen == *listen {
			return errors.New("-admin-listen must differ from -listen: agents must not reach the approval page")
		}
		if *approvalTimeout <= 0 {
			return errors.New("-approval-timeout must be positive")
		}
		broker := approval.NewBroker(*approvalTimeout, 0)
		var err error
		if admin, err = approval.NewAdmin(broker, approvers); err != nil {
			return err
		}
		approver = guard.BrokerApprover{Broker: broker}
	case needsApproval:
		logger.Warn("policy has tools that require approval but no approver is configured; those tools will always be refused")
	}

	auditLog, err := audit.Open(*auditPath)
	if err != nil {
		return err
	}
	defer auditLog.Close()

	handler, err := proxy.New(proxy.Config{
		Upstreams:  upstreams,
		Authorizer: authorizer,
		Approver:   approver,
		Audit:      guard.AuditRecorder{Log: auditLog},
		Logger:     logger,
	})
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// No WriteTimeout on the gateway: SSE responses and calls waiting for
	// approval are long-lived.
	servers := []*http.Server{{Addr: *listen, Handler: handler, ReadHeaderTimeout: 10 * time.Second}}
	if admin != nil {
		servers = append(servers, &http.Server{Addr: *adminListen, Handler: admin,
			ReadHeaderTimeout: 10 * time.Second, WriteTimeout: 30 * time.Second})
	}

	errc := make(chan error, len(servers))
	for _, srv := range servers {
		go func() { errc <- srv.ListenAndServe() }()
	}
	logger.Info("mcpguard listening", "addr", *listen, "admin_addr", *adminListen,
		"servers", len(upstreams), "audit_db", *auditPath)

	select {
	case err = <-errc:
	case <-ctx.Done():
		err = nil
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, srv := range servers {
		_ = srv.Shutdown(shutdownCtx)
	}
	return err
}
