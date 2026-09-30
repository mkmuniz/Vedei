# ADR-001 — Reuse betterleaks instead of reimplementing secret detection

**Status:** accepted · 2026-09-26

## Context

Secret scanning is mature and crowded. betterleaks ships 463 rules, 218 of them
with live validation; kingfisher ships 1,051. Both are backed by paid
maintainers. Building a competing corpus is years of work, and rule count is
the first thing anyone compares.

betterleaks is MIT. Its v2 is explicitly designed to be consumed as a library:
module path `/v2`, a Scanner/Analyzer/Pipeline split, and a documented
`examples/` directory.

## Decision

vedei imports betterleaks as its secret engine and writes none of its own
secret rules. All original effort goes to Brazilian sensitive data, which no
maintained open-source tool covers.

New secret rules are contributed upstream, not forked here.

## Consequences

**Good.** We inherit 463 rules on day one. We become complementary rather than
competing, which makes upstream collaboration possible.

**Bad.** We depend on another project's release cadence and API. v2 is still on
a branch.

**Mitigation.** The `detect.Engine` interface isolates the dependency. Swapping
v1 for v2 changes one package, `engine/secrets`.
