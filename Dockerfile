# syntax=docker/dockerfile:1
FROM golang:1.27 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
# Pure-Go SQLite driver, so a static binary with no C toolchain.
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/ ./cmd/mcpguard ./cmd/sampleserver ./cmd/sampleagent

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/mcpguard /out/sampleserver /out/sampleagent /usr/local/bin/
USER nonroot:nonroot
EXPOSE 8080 8081 9090
ENTRYPOINT ["/usr/local/bin/mcpguard"]
