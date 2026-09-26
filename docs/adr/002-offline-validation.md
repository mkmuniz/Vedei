# ADR-002 — Personal data is validated structurally, never against a registry

**Status:** accepted · 2026-09-26

## Context

"Validate" means two different things in this project. For a secret it means
"is this credential live", answered by an HTTP request to the provider. For
personal data it could mean either "does the check digit close" or "does this
person exist".

The second reading is available: CPF lookup services exist.

## Decision

nadzor validates structure only. It computes check digits, Luhn, ISPB
membership and format. It never queries an official registry, a bureau or any
third-party service to confirm that a person or company exists.

nadzor states "this is a structurally valid CPF". It never states whose.

## Consequences

**Good.** The Brazilian engine is fully offline. That removes rate limiting,
timeouts, SSRF surface and third-party dependency, and makes it fast and
deterministic enough for the hot path — the agent hook and logging middleware.

**Good.** It avoids creating a worse privacy problem than the one being
detected. Sending a CPF found in a log to an external lookup is itself a
serious LGPD exposure.

**Bad.** We cannot distinguish a structurally valid CPF that was never issued
from one that was. Test fixtures using valid-but-fake CPFs will be reported.

**Accepted.** That is the correct trade. The M5 corpus and context-based
confidence scoring reduce the noise; querying a registry is not an option.
