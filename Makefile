GO ?= go

.PHONY: test race fuzz scenarios demo site check

## test: run all tests
test:
	$(GO) test ./...

## race: run all tests with the race detector
race:
	$(GO) test -race -count=1 ./...

## fuzz: run each fuzzer for 30 seconds
fuzz:
	$(GO) test ./internal/policy -run '^$$' -fuzz '^FuzzParse$$' -fuzztime 30s
	$(GO) test ./internal/policy -run '^$$' -fuzz '^FuzzMatchArguments$$' -fuzztime 30s
	$(GO) test ./internal/proxy -run '^$$' -fuzz '^FuzzInspect$$' -fuzztime 30s
	$(GO) test ./internal/proxy -run '^$$' -fuzz '^FuzzScanEventStream$$' -fuzztime 30s
	$(GO) test ./internal/scan -run '^$$' -fuzz '^FuzzRules$$' -fuzztime 30s

## scenarios: play the MCP scenario suite and write a results file
scenarios:
	$(GO) run ./evals/scenarios

## demo: scripted agent, gateway and two MCP servers in Docker
demo:
	docker compose -f deploy/compose/docker-compose.yml up --build --abort-on-container-exit

## site: regenerate the showcase page data from evals/results
site:
	python3 site/build.py

## check: what CI checks, minus the fuzzers and the image build
check:
	scripts/check-secrets.sh
	test -z "$$(gofmt -l .)"
	$(GO) vet ./...
	$(GO) test -race -count=1 ./...
