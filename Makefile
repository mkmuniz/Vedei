BINARY  := vedei
# The hook client is a separate binary because its size is its whole point:
# it skips the rule set and the dependency tree behind it, so it loads in ~1 ms
# instead of ~7 ms. Measured: 8.7 ms per hook call against 29 ms.
HOOKBIN := vedei-hook
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build test lint bench cover clean install-tools all fuzz security vuln sast latency

all: lint test build

build:
	go build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(BINARY) ./cmd/vedei
	go build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(HOOKBIN) ./cmd/vedei-hook

# Prints the hook latency on both paths, with and without a daemon. This is the
# number the M3 exit criterion is about, so it is a target rather than a note.
latency: build
	go test -race=false -run TestHookLatency -v -count=1 ./cmd/vedei-hook/

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

# vedei is a security tool: it must pass its own class of scanner.
#
# go test -fuzz takes exactly one target, so each is named. Check-digit
# arithmetic, the record rewriter and the ignore matcher are the three places
# where a small amount of code meets a large input space, and where the failure
# is quiet: a wrong answer rather than a crash.
FUZZTIME ?= 60s
FUZZ_DETECT := FuzzValidatorsNeverPanic FuzzExtractYieldsOnlyValidValues \
               FuzzExtractIsDeterministic FuzzCPFCheckDigits \
               FuzzCNPJCheckDigits FuzzExtract
FUZZ_TRANSCRIPT := FuzzScrubRecord_PreservesMeaning FuzzScrubRecord_NumbersSurviveExactly \
                   FuzzScrubRecord_RedactionKeepsItValid FuzzReadableText
FUZZ_SCAN := FuzzParseIgnore FuzzIgnoreStack FuzzIsBinary

fuzz:
	@for t in $(FUZZ_DETECT); do \
		echo "== $$t"; go test -run '^$$' -fuzz "^$$t$$" -fuzztime=$(FUZZTIME) ./detect/br/ || exit 1; \
	done
	@for t in $(FUZZ_TRANSCRIPT); do \
		echo "== $$t"; go test -run '^$$' -fuzz "^$$t$$" -fuzztime=$(FUZZTIME) ./transcript/ || exit 1; \
	done
	@for t in $(FUZZ_SCAN); do \
		echo "== $$t"; go test -run '^$$' -fuzz "^$$t$$" -fuzztime=$(FUZZTIME) ./scan/ || exit 1; \
	done

# Everything the security audit runs, so it is one command rather than a
# document describing four.
security: lint vuln sast
	@echo "govulncheck, gosec and golangci-lint all clean"

vuln:
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...

# gosec standalone, on top of the copy golangci-lint runs. The flags are the
# point: every suppression has to name its rule and say why, or this fails.
# A "#nosec" with no reason is how a real finding gets silenced by someone in
# a hurry and never looked at again.
sast:
	go run github.com/securego/gosec/v2/cmd/gosec@latest -quiet -severity low -confidence low \
		-exclude-dir=testdata -nosec-require-justification -nosec-require-rules ./...

install-tools:
	go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest

clean:
	rm -rf bin coverage.out

# Rebuilds the embedded ISPB registry from the upstream dataset.
update-ispb:
	go run ./internal/cmd/genispb
	go test ./detect/br/ -run TestISPB
