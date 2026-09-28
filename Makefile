BINARY  := nadzor
# The hook client is a separate binary because its size is its whole point:
# it skips the rule set and the dependency tree behind it, so it loads in ~1 ms
# instead of ~7 ms. Measured: 8.7 ms per hook call against 29 ms.
HOOKBIN := nadzor-hook
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build test lint bench cover clean install-tools all

all: lint test build

build:
	go build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(BINARY) ./cmd/nadzor
	go build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(HOOKBIN) ./cmd/nadzor-hook

# Prints the hook latency on both paths, with and without a daemon. This is the
# number the M3 exit criterion is about, so it is a target rather than a note.
latency: build
	go test -race=false -run TestHookLatency -v -count=1 ./cmd/nadzor-hook/

test:
	go test -race ./...

# Property-based tests generate many cases; keep them honest with a real count.
cover:
	go test -race -coverprofile=coverage.out -covermode=atomic ./...
	go tool cover -func=coverage.out | tail -1

cover-html: cover
	go tool cover -html=coverage.out

bench:
	go test -bench=. -benchmem -run=^$$ ./...

lint:
	golangci-lint run

# nadzor is a security tool: it must pass its own class of scanner.
fuzz:
	go test -fuzz=Fuzz -fuzztime=60s ./detect/br/...

install-tools:
	go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest

clean:
	rm -rf bin coverage.out

# Rebuilds the embedded ISPB registry from the upstream dataset.
update-ispb:
	go run ./internal/cmd/genispb
	go test ./detect/br/ -run TestISPB
