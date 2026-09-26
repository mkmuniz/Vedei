# ADR-004 — Model output is a signal, never a filter

**Status:** accepted · 2026-09-26

## Context

If a model can classify a finding as a false positive, the tempting next step
is to let it drop the finding, cutting the triage queue.

## Decision

Model classification attaches an attribute to a finding and may reorder a
triage queue. It may never discard a finding, downgrade it below the reporting
threshold, or prevent it from appearing in a report.

Only deterministic rules — check digit failure, an explicit `.nadzorignore`
entry, a configured filter — remove a finding.

## Consequences

**Good.** A nondeterministic component can never silently hide a real leak.
Behaviour stays reproducible: the same input yields the same findings.

**Bad.** The queue stays as long as the detector makes it. The model helps you
read it faster, not make it shorter.

**Accepted.** A missed credential costs more than an analyst's minute.
