## What this changes

<!-- One or two sentences. What is different after this merges? -->

## Why

<!-- The problem, not the solution. Link the issue if there is one. -->

Closes #

## Checklist

- [ ] `make test` passes
- [ ] `make lint` reports zero issues
- [ ] New code does not lower coverage

### If this adds or changes a detector

- [ ] The validator lives in `detect/br/` and has **no** dependencies outside the standard library
- [ ] **Property-based tests**, not examples: generated valid values pass, corrupted values fail, real-world masks are equivalent
- [ ] Edge cases specific to this document type are covered, and the PR says why those are the ones that matter
- [ ] Entries added to `corpus/`: one true positive and one value that looks right but must not be reported
- [ ] Confidence reflects what the check digit actually proves — if the scheme has a weak spot, it is documented in the code

### If this touches anything a detected value passes through

- [ ] No path sends `Finding.Raw` out of the process — not to a report, a log, telemetry, or a model
- [ ] Redaction still hides the identifying part of the value
- [ ] Findings with `ValidityInvalid` still never leave the engine

## Trade-offs and limitations

<!-- What this does NOT do, what you chose not to handle, and why.
     A PR that claims no limitations gets a slower review, not a faster one. -->

## How to verify

<!-- Commands a reviewer can run, or the output that shows it working. -->

```
```

---

<sub>By opening this PR you agree it is licensed under the [MIT License](../LICENSE) and that you follow the [Code of Conduct](CODE_OF_CONDUCT.md).</sub>
