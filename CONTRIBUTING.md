# Contributing

## Before you start

Read [`ARCHITECTURE.md`](ARCHITECTURE.md) §9 — the list of what is forbidden in
this codebase. A PR that breaks one of those six rules will not be merged, no
matter how good the rest of it is.

## Adding a Brazilian detector

Every detector is three things, and a PR needs all three.

**1. A pure validator** in `detect/br/<name>.go`

No dependencies, no IO, no network. Signature:

```go
// ValidateFoo reports whether s is a structurally valid Foo.
// It validates structure only — never identity, never against a registry.
func ValidateFoo(s string) bool
```

**2. Property-based tests** in `detect/br/<name>_test.go`

Example-based tests are not enough for check-digit code. A PR needs:

```go
func TestFoo_GeneratedAreValid(t *testing.T)   // N generated valid -> all pass
func TestFoo_CorruptedFail(t *testing.T)       // flip one digit      -> all fail
func TestFoo_KnownEdgeCases(t *testing.T)      // repeated sequences, etc.
```

Use at least 10,000 generated cases. State in the PR why the edge cases you
chose are the ones that matter for this document type.

**3. Extraction and its corpus**

A regex in `detect/br/extract.go` tolerant of the real-world masks, plus
entries in `corpus/` covering both a true positive and a false positive
(a value that looks right and must not be reported).

## Adding a secret rule

Don't. Secret rules belong upstream in
[betterleaks](https://github.com/betterleaks/betterleaks) — open the PR there
and vedei inherits it. This keeps one corpus instead of two diverging ones.

## Pull requests

1. Open an issue first and say you are working on it.
2. One concern per PR.
3. `make test && make lint` passes locally.
4. New code does not lower coverage.
5. Commit messages in English, imperative mood, no AI co-author lines.

## What gets rejected

- A validator without property-based tests.
- Anything that sends a detected value out of the process.
- A detector for a document with no check digit, presented as high confidence.
  RG is the example: it has no national standard and cannot be validated.
- Dependencies in `detect/br/`. That package stays pure.
