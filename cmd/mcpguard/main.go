// Command mcpguard runs the MCP Guard gateway.
//
//	mcpguard -listen 127.0.0.1:8080 -policy policy.yaml -upstream sample=http://127.0.0.1:9001
//
// The agent then uses http://127.0.0.1:8080/sample/mcp as its MCP endpoint,
// sending its bearer token in the Authorization header.
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

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	if err := run(logger); err != nil {
		logger.Error("mcpguard failed", "err", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	upstreams := upstreamFlags{}
	listen := flag.String("listen", "127.0.0.1:8080", "address to listen on")
	flag.Var(upstreams, "upstream", "MCP server as name=url (repeatable); served at /{name}/mcp")
	policyPath := flag.String("policy", "", "path to the policy YAML file (required unless -insecure-allow-all)")
	allowAll := flag.Bool("insecure-allow-all", false, "run with no policy and allow everything (evaluation baseline only)")
	flag.Parse()

	// Bad configuration stops startup; the gateway never runs half-configured.
	var authorizer proxy.Authorizer
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
			for server := range agent.Servers {
				if _, ok := upstreams[server]; !ok {
					return fmt.Errorf("policy: agent %q refers to server %q, which has no -upstream", agent.Name, server)
				}
			}
		}
		logger.Info("policy loaded", "path", *policyPath, "policy_version", pol.Hash(), "agents", len(pol.Agents))
		authorizer = guard.PolicyAuthorizer{Engine: policy.NewEngine(pol)}
	}

	handler, err := proxy.New(proxy.Config{Upstreams: upstreams, Authorizer: authorizer, Logger: logger})
	if err != nil {
		return err
	}

	// No WriteTimeout: SSE responses are long-lived.
	srv := &http.Server{Addr: *listen, Handler: handler, ReadHeaderTimeout: 10 * time.Second}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	logger.Info("mcpguard listening", "addr", *listen, "servers", len(upstreams))

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
}
