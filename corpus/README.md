# Corpus

Labeled examples that measure what vedei catches and what it cries wolf over.

A scanner's worth is not that it compiles. It is precision and recall on real
input, and neither can be settled by reading the rules. M5 assumed Portuguese
placeholders like `senhapadrao` would be reported as secrets; measured here,
they were not. The real gap ran the other way: a credential under a Portuguese
key name was found 29% of the time, against 100% under an English one. That is
what labeled data is for — it tells you which way a bias runs. This directory
is that data.

## Format

One directive per line in `cases/*.txt`:

```
expect cpf  529.982.247-25     # must be found, as a cpf
reject      529.982.247-00     # must not be reported — wrong check digit
```

- **`expect <type> <value>`** — a true positive. The engine must report a
  finding of `<type>` over `<value>`. A miss is a recall failure: a leak walked
  past.
- **`reject <value>  # reason`** — a false positive. The engine must report
  nothing. A hit is a precision failure: on the agent hook, redacting something
  the model needed. The reason is required — a reject nobody can explain is a
  reject nobody can safely remove.

Everything after `#` is a comment.

## Running

```bash
make corpus          # or: go test ./corpus/
```

The gate is strict: every `expect` must be found and every `reject` must stay
quiet. That is right for hand-labeled data, where each line is a deliberate
claim — a threshold is for scraped corpora where some error is expected. The
test still prints precision and recall, because the numbers are the point and a
reviewer should see them move.

## Adding a case

When a scan produces a false positive, add the value here as a `reject` with the
reason, then fix the detector until this test passes again. When a detector
gains a document type, add `expect` cases for it. The file
`cases/false-positives.txt` is the running record of what scanning the real
world actually produced — every entry in it was once a wrong finding.

No `.vedeiignore` entry is needed. `corpus/cases/` is silenced by path — the one
path rule in this repository — so the self-scan does not report the values that
live here. That rule also means a value pasted into these files is never
reported by `vedei scan`, which is safe only because every line must be a
labeled `expect` or `reject`: the corpus test fails on anything else.
