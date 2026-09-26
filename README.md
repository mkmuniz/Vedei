<div align="center">

<img src="assets/nadzor-logo.svg" width="600" alt="nadzor — what shouldn't leave, doesn't">

**Finds and validates Brazilian sensitive data and leaked secrets — offline, with check digits, before they reach your logs, your CI, or your AI agent's context.**

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Go](https://img.shields.io/badge/go-1.25-00ADD8.svg)](go.mod)
[![Status](https://img.shields.io/badge/status-early%20development-orange.svg)](#status)

</div>

---

## Status

**Nothing here works yet.** This repository is at M0 — the design is settled, the code is not written. There is no release, no binary, no install path. If you found this looking for a working tool today, use [betterleaks](https://github.com/betterleaks/betterleaks) or [kingfisher](https://github.com/mongodb/kingfisher); nadzor is built on top of the former, not against it.

What this README describes is the specification being implemented. See [Roadmap](#roadmap) for what exists and what doesn't.

## Why this project exists

Secret scanning is a solved and crowded problem. Betterleaks ships 463 rules, Kingfisher ships 1,051. Rebuilding that corpus would take years and would still lose. So nadzor doesn't rebuild it — it **imports betterleaks as a library** (MIT) and spends all of its effort on the part nobody has built.

That part is **Brazilian sensitive data**. Searching GitHub for a maintained open-source tool that detects and validates CPF, CNPJ, CNH, Pix keys, card PANs and Pix end-to-end IDs returns nothing. Not "underserved" — empty. And in a country running the largest instant-payment system in the world, under LGPD and PCI-DSS, that gap costs real money.

There's a second reason, and it's architectural. Betterleaks validates a secret by **asking the provider over HTTP** — which is why it needs a rate limiter, a per-redirect-chain timeout budget, and why the destination of those requests is worth worrying about. Brazilian personal data doesn't work that way. A CPF is validated by a mod-11 check digit. A card number by Luhn. A Pix key by its type. An E2EID by its structure and its ISPB.

**All of it offline.** No network, no rate limits, no SSRF surface, no provider to be throttled by. That isn't a different architecture — it's a simpler and safer one.

## What "validate" means here

This distinction drives the whole design, so it comes before the feature list.

| | Secret (API key, token) | Personal data (CPF, card) |
|---|---|---|
| Validation answers | **Is it live?** | **Is it structurally real?** |
| Mechanism | HTTP request to the provider | Local arithmetic |
| Network | required | **none** |
| Latency | 50–500 ms | microseconds |
| Attack surface of validating | SSRF, exfiltration, rate limits | none |
| What you do next | revoke / rotate | redact / remove, possibly notify |

**The line nadzor will not cross:** personal data is validated for *structure*, never by querying an official registry. Checking a CPF found in a log against a government database would create a far worse privacy problem than the one being detected. nadzor tells you `123.456.789-09` is a structurally valid CPF. It never tells you whose.

## What it detects

| Data | Offline validation | Algorithm |
|---|:---:|---|
| **CPF** | ✅ | Mod 11, two check digits; repeated-sequence rejection |
| **CIN** (Carteira de Identidade Nacional) | ✅ | Uses the CPF as the national number — same validation |
| **CNPJ** (numeric) | ✅ | Mod 11, weights `5,4,3,2,9,8,7,6,5,4,3,2` |
| **CNPJ** (alphanumeric) | ✅ | Mod 11 with `ASCII − 48` for letters — **in force since 2026-07-06** |
| **CNH** | ✅ | Mod 11, 11-digit variant |
| **PIS / NIS / NIT** | ✅ | Mod 11, weights `3,2,9,8,7,6,5,4,3,2` |
| **Título de eleitor** | ✅ | Two check digits, mod 11, embedded state code |
| **CNS** (SUS card) | ✅ | Weighted sum ≡ 0 (mod 11) |
| **Card PAN** | ✅ | Luhn + BIN range for the brand |
| **Pix key** | ✅ | Per type: CPF/CNPJ (check digit), email, phone (`+55` + valid area code), EVP (UUID v4) |
| **Pix E2EID** | ✅ | `E` + ISPB(8) + `YYYYMMDDHHMM` + 11 alphanumerics; ISPB checked against the registry |
| **Branch / account** | ⚠️ | Check digit varies per institution — needs a per-bank table |
| **RG** | ❌ | **No national standard.** No algorithm can validate it. Contextual heuristic only, always low confidence |
| **Secrets** (463 rules) | via provider | Delegated to [betterleaks](https://github.com/betterleaks/betterleaks) |

Most detectors that exist today match CNPJ with `\d{14}`. That has been wrong since July 2026.

The ISPB registry comes from [`guibranco/BancosBrasileiros`](https://github.com/guibranco/BancosBrasileiros) — 400+ institutions, updated daily from official sources. nadzor consumes it; it does not maintain its own copy of the truth.

## Where it runs

Four surfaces, one engine. They ship in this order, and only the first is the MVP.

| Surface | What it does | Status |
|---|---|---|
| **AI agent context** | A `PostToolUse` hook for Claude Code and Codex. When the agent runs `cat .env`, the secret and the CPF are redacted before the output reaches the model | 🎯 MVP |
| **CI/CD** | CLI, GitHub Action, SARIF for GitHub Code Scanning, pre-commit and pre-receive hooks | planned |
| **Application runtime** | A `slog.Handler` and HTTP middleware that redact before writing — prevention, not detection | planned |
| **Observability** | An OpenTelemetry collector processor for logs and traces, where PANs and CPFs actually leak | planned |

## Design principles (non-negotiable)

1. **A detected value never reaches a language model.** Not in triage, not in explanation, not in telemetry. A tool that finds a leaked credential and posts it to an LLM API has created a new leak to solve an old one. This is enforced by a CI test that asserts no outbound payload ever contains a detected value.
2. **Personal data is validated structurally, never against an official registry.**
3. **A model's output is a signal, never a filter.** Nondeterministic classification may reorder a triage queue. It may not silently discard a finding.
4. **Fail open on the redaction path, fail closed on the reporting path.** A crash in the agent hook must not break the user's session; a crash during a CI scan must not be reported as "clean".
5. **Distinct exit codes for "found something" and "the scan broke".** A pipeline must never mistake a failed scan for a clean one.
6. **No false positives on structurally invalid values.** If the check digit doesn't close, it is not a CPF, and nadzor does not report it.
7. **Thresholds are calibrated per language.** English-tuned heuristics misbehave on Portuguese source; see [Roadmap](#roadmap) M5.

## Roadmap

| | Milestone | Status |
|---|---|---|
| M0 | Foundation — repo, license, CI, ADRs | 🚧 in progress |
| M1 | Brazilian detectors + offline validation | ⬜ |
| M2 | Secret engine via betterleaks | ⬜ |
| M3 | **MVP — AI agent context hook** | ⬜ |
| M4 | CLI, CI/CD, SARIF | ⬜ |
| M5 | Multilingual false-positive corpus + pt-BR calibration | ⬜ |
| M6 | Runtime SDK | ⬜ |
| M7 | AI layer — assisted triage, rule generation, MCP server | ⬜ |
| M8 | Observability collector | ⬜ |
| M9 | Secret validation with destination allowlist | ⬜ |
| M10 | v1.0 | ⬜ |

M5 deserves a note, because it is the one finding here that is original. Betterleaks filters candidates with a BPE "token efficiency" ratio against a 33,775-word **English** dictionary and a fixed threshold of 2.5 characters per token. Measured with its own embedded tokenizer: `defaultpassword` scores 7.50 and is correctly discarded as prose, while `senhapadrao` scores 2.20 and is reported as a secret. Real secrets sit at 1.0–1.6. In English the gap between prose and secret is comfortable; in Portuguese it nearly vanishes. A Portuguese codebase produces more false positives, and no one has measured it. M5 turns that into a versioned corpus and a CI-enforced metric.

## Project structure

```
detect/br/        # the core: pure validators, zero dependencies
detect/engine.go  # the Engine interface — insulation from betterleaks' v2 API
engine/secrets/   # betterleaks wrapped behind that interface
redact/           # format-preserving redaction
report/           # JSON, JSONL, SARIF
stream/           # stdin -> stdout, the MVP path
hooks/            # Claude Code and Codex hooks
corpus/           # multilingual false-positive corpus
```

## The name

**Надзор** (*nadzor*) is Russian for *oversight* or *supervision* — it is the word used for regulatory supervision. It is `dozor` (the watch, the patrol) with the prefix `nad-` (over, above).

A tool whose job is to inspect what passes a boundary and enforce a rule about it is not a guard. It is oversight.

## Contributing

Not yet — there is nothing to contribute to. Once M1 lands, `CONTRIBUTING.md` will describe how a new detector and its test corpus get accepted.

## Security

Found a vulnerability? Please do not open a public issue. See `SECURITY.md` (coming with M0).

## License

[MIT](LICENSE) — the same as [betterleaks](https://github.com/betterleaks/betterleaks), which nadzor builds on.
