<div align="center">

<img src="assets/nadzor-logo.svg" width="600" alt="nadzor — what shouldn't leave, doesn't">

**Finds and validates Brazilian sensitive data and leaked secrets — offline, with check digits, before they reach your logs, your CI, or your AI agent's context.**

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Go](https://img.shields.io/badge/go-1.27-00ADD8.svg)](go.mod)
[![CI](https://github.com/mkmuniz/nadzor/actions/workflows/ci.yml/badge.svg)](https://github.com/mkmuniz/nadzor/actions/workflows/ci.yml)
[![Status](https://img.shields.io/badge/status-early%20development-orange.svg)](#status)

[Português](README.pt-BR.md)

</div>

---

## Status

**M0 done — scaffolding only. No detection works yet.** Need a working tool today? Use [betterleaks](https://github.com/betterleaks/betterleaks) or [kingfisher](https://github.com/mongodb/kingfisher). nadzor builds on the former.

## What it detects

| Data | Offline validation | Algorithm |
|---|:---:|---|
| **CPF** | ✅ | Mod 11, two check digits; repeated-sequence rejection |
| **CIN** | ✅ | Uses the CPF as the national number — same validation |
| **CNPJ** numeric | ✅ | Mod 11, weights `5,4,3,2,9,8,7,6,5,4,3,2` |
| **CNPJ** alphanumeric | ✅ | Mod 11 with `ASCII − 48` for letters — **in force since 2026-07-06** |
| **CNH** | ✅ | Mod 11, 11-digit variant |
| **PIS / NIS / NIT** | ✅ | Mod 11, weights `3,2,9,8,7,6,5,4,3,2` |
| **Título de eleitor** | ✅ | Two check digits, mod 11, embedded state code |
| **CNS** (SUS card) | ✅ | Weighted sum ≡ 0 (mod 11) |
| **Card PAN** | ✅ | Luhn + BIN range |
| **Pix key** | ✅ | Per type: CPF/CNPJ, email, phone, EVP (UUID v4) |
| **Pix E2EID** | ✅ | `E` + ISPB(8) + `YYYYMMDDHHMM` + 11 alphanumerics |
| **Branch / account** | ⚠️ | Check digit varies per institution |
| **RG** | ❌ | **No national standard.** Contextual heuristic only, low confidence |
| **Secrets** (463 rules) | via provider | Delegated to [betterleaks](https://github.com/betterleaks/betterleaks) |

Most detectors match CNPJ with `\d{14}`. That has been wrong since July 2026.

ISPB registry from [`guibranco/BancosBrasileiros`](https://github.com/guibranco/BancosBrasileiros) — 400+ institutions, updated daily.

## Where it runs

| Surface | What it does | Status |
|---|---|---|
| **AI agent context** | `PostToolUse` hook for Claude Code and Codex. `cat .env` reaches the model redacted | 🎯 MVP |
| **Agent transcripts** | Audits what already leaked into `~/.claude/projects/*.jsonl` | 🎯 MVP |
| **CI/CD** | CLI, GitHub Action, SARIF, pre-commit, pre-receive | planned |
| **Application runtime** | `slog.Handler` and HTTP middleware that redact before writing | planned |
| **Observability** | OpenTelemetry collector processor for logs and traces | planned |

## Why it exists

Secret scanning is solved and crowded — betterleaks ships 463 rules, kingfisher 1,051. Rebuilding that corpus loses. So nadzor **imports betterleaks** (MIT) and spends everything on what nobody built: **Brazilian sensitive data**. No maintained open-source tool detects CPF, CNPJ, CNH, Pix keys, card PANs and E2EIDs. Not underserved — empty.

The second reason is architectural. betterleaks validates a secret by asking the provider over HTTP, which needs a rate limiter, a timeout budget, and care about where those requests go. Brazilian personal data doesn't work that way: a CPF is a mod-11 check digit, a card is Luhn, a Pix key is its type. **All offline.** No network, no rate limits, no SSRF surface. Simpler and safer, not just different.

### Why the transcript matters

A `.env` has protections — gitignore, file permissions, a vault. `~/.claude/projects/*.jsonl` has none: plaintext, no encryption, no rotation, no expiry, no security tool watching it. Whoever reads the disk — malware, a stolen laptop, an exfiltrated backup — reads every secret the agent ever touched.

nadzor reduces what lands there and shows what already did. It does not replace disk encryption.

Documented upstream: [#44868](https://github.com/anthropics/claude-code/issues/44868), [#50014](https://github.com/anthropics/claude-code/issues/50014), [#95680](https://github.com/anthropics/claude-code/issues/95680).

## What "validate" means here

| | Secret | Personal data |
|---|---|---|
| Answers | **Is it live?** | **Is it structurally real?** |
| Mechanism | HTTP to the provider | Local arithmetic |
| Network | required | **none** |
| Latency | 50–500 ms | microseconds |
| Next step | revoke / rotate | redact / remove |

**The line nadzor will not cross:** personal data is validated for *structure*, never by querying an official registry. nadzor says `123.456.789-09` is a structurally valid CPF. Never whose.

## Design principles (non-negotiable)

1. **A detected value never reaches a language model.** Enforced by a blocking CI test.
2. **Personal data is validated structurally, never against a registry.**
3. **Model output is a signal, never a filter.** It may reorder a queue; it may not discard a finding.
4. **Fail open on redaction, fail closed on reporting.** Breaking a session is worse than missing a redaction; reporting "clean" on a broken scan is worse than a red build.
5. **Distinct exit codes:** `0` clean, `3` findings, `1` error.
6. **No false positives on structurally invalid values.** If the check digit fails, it is not a CPF.
7. **Thresholds calibrated per language.** English-tuned heuristics misbehave on Portuguese source.

Full records in [`docs/adr/`](docs/adr/).

## Roadmap

| | Milestone | Status |
|---|---|---|
| M0 | Foundation | ✅ |
| M1 | Brazilian detectors + offline validation | ⬜ |
| M2 | Secret engine via betterleaks | ⬜ |
| M3 | **MVP — AI agent surface** | ⬜ |
| M4 | CLI, CI/CD, SARIF, transcript scrub | ⬜ |
| M5 | Multilingual false-positive corpus + pt-BR calibration | ⬜ |
| M6 | Runtime SDK | ⬜ |
| M7 | AI layer | ⬜ |
| M8 | Observability collector | ⬜ |
| M9 | Secret validation + destination allowlist | ⬜ |
| M10 | v1.0 | ⬜ |

Features, implementation steps, test strategy and exit criteria per stage: [`MILESTONES.md`](MILESTONES.md). Component design and performance budgets: [`ARCHITECTURE.md`](ARCHITECTURE.md).

**On M5.** betterleaks filters candidates with a BPE token-efficiency ratio against a 33,775-word **English** dictionary and a fixed 2.5 threshold. Measured with its own embedded tokenizer: `defaultpassword` scores 7.50 and is correctly discarded; `senhapadrao` scores 2.20 and is reported as a secret. Real secrets sit at 1.0–1.6. In English the gap is comfortable; in Portuguese it nearly vanishes. M5 turns that into a versioned corpus and a CI-enforced metric.

## Project structure

```
detect/br/        # the core: pure validators, zero dependencies
detect/engine.go  # the Engine interface — insulation from betterleaks' v2 API
engine/secrets/   # betterleaks wrapped behind that interface
redact/           # format-preserving redaction
report/           # JSON, JSONL, SARIF
stream/           # stdin -> stdout, the MVP path
transcript/       # agent session log reader
hooks/            # Claude Code and Codex hooks
corpus/           # multilingual false-positive corpus
```

## The name

**Надзор** (*nadzor*) is Russian for *oversight* — the word used for regulatory supervision. It is `dozor` (the watch) with the prefix `nad-` (over, above).

A tool that inspects what passes a boundary and enforces a rule about it is not a guard. It is oversight.

## Contributing · Security · License

- New detector? Read [`CONTRIBUTING.md`](CONTRIBUTING.md) — property-based tests are mandatory for check-digit code.
- Found a vulnerability? [`SECURITY.md`](SECURITY.md). Do not open a public issue.
- [MIT](LICENSE), same as betterleaks.
