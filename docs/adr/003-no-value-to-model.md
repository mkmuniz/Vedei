# ADR-003 — A detected value never reaches a language model

**Status:** accepted · 2026-09-26

## Context

The M7 AI layer wants a model to help triage findings: is this a real secret,
a test fixture, a documentation example? The obvious implementation sends the
finding to a model. The finding contains the secret.

## Decision

A detected value is never included in any request to a language model — not in
triage, not in explanation, not in telemetry, not in a severity narrative.

The AI layer receives redacted context only: file path, variable name, the line
with the value masked, the shape of the value, entropy, token ratio and
redacted surrounding lines.

## Consequences

**Good.** The worst possible failure for this project — a tool that finds a
leaked credential and leaks it further — is structurally impossible rather
than merely discouraged.

**Bad.** Triage accuracy is lower than it would be with the value present.

**Enforcement.** A CI test intercepts every outbound payload from `ai/` and
fails if any contains a detected value. The test is blocking. This ADR is not
a guideline; it is a test.
