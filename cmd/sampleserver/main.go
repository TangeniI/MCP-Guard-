// Command sampleserver runs the demo MCP server (echo, add) over Streamable HTTP.
package main

import (
	"flag"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/TangeniI/MCP-Guard-/internal/sampleserver"
)

func main() {
	addr := flag.String("listen", "127.0.0.1:9001", "address to listen on")
	flag.Parse()

	srv := &http.Server{Addr: *addr, Handler: sampleserver.Handler(), ReadHeaderTimeout: 10 * time.Second}
	slog.Info("sample MCP server listening", "addr", *addr)
	if err := srv.ListenAndServe(); err != nil {
		slog.Error("server stopped", "err", err)
		os.Exit(1)
	}
}
