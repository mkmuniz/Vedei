BINARY  := nadzor
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build test lint bench cover clean install-tools all

all: lint test build

build:
	go build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(BINARY) ./cmd/nadzor

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
