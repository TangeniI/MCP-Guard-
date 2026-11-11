// Command mcpguard runs the MCP Guard gateway.
//
//	mcpguard -listen 127.0.0.1:8080 -upstream files=http://127.0.0.1:9001
//
// The agent then uses http://127.0.0.1:8080/files/mcp as its MCP endpoint.
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
	flag.Parse()

	// Bad configuration stops startup; the gateway never runs half-configured.
	handler, err := proxy.New(proxy.Config{Upstreams: upstreams, Logger: logger})
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
