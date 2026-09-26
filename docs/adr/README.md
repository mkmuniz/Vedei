# Architecture Decision Records

One file per decision. Each states the context, the decision and what it costs.
A decision is superseded, never edited.

| # | Decision | Status |
|---|---|---|
| [001](001-reuse-betterleaks.md) | Reuse betterleaks instead of reimplementing secret detection | accepted |
| [002](002-offline-validation.md) | Personal data is validated structurally, never against a registry | accepted |
| [003](003-no-value-to-model.md) | A detected value never reaches a language model | accepted |
| [004](004-model-output-is-signal.md) | Model output is a signal, never a filter | accepted |
| [005](005-fail-open-fail-closed.md) | Fail open on redaction, fail closed on reporting | accepted |
