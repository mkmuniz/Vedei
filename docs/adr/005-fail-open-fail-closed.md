# ADR-005 — Fail open on redaction, fail closed on reporting

**Status:** accepted · 2026-09-26

## Context

vedei runs on two kinds of path with opposite failure costs.

On the redaction path — the agent hook, the logging middleware — it sits
between a user and their work. On the reporting path — CI, a scan — it answers
a question someone will act on.

## Decision

**Redaction path fails open.** An internal error lets the text through
unmodified. Breaking the user's session is worse than failing to redact once.

**Reporting path fails closed.** An error during a scan fails the scan with a
distinct exit code. Reporting "clean" when the scan broke is worse than a red
build.

Exit codes: `0` clean, `3` findings, `1` operational error. A pipeline must
never mistake a broken scan for a clean one.

## Consequences

**Good.** Each path gets the behaviour its risk profile demands.

**Bad.** Two different error policies in one codebase is a thing contributors
will get wrong.

**Mitigation.** It is listed in `ARCHITECTURE.md` §9 as a review rule, and the
fail-open behaviour has a dedicated test that injects a panicking engine.
