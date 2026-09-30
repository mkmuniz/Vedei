# ADR-006 — A daemon holds the compiled rules, and the hook client stays small

**Status:** accepted · 2026-09-27

## Context

The agent hook runs on every tool result, inside someone else's latency
budget. M3 set a budget of 10 ms p95 for it. That number was a guess made
before anything existed to measure.

The first measurement of the finished hook was 28.9 ms p95, and the breakdown
explained why the guess was unreachable:

| cost | time |
| --- | ---: |
| detection itself | 0.26 ms |
| compiling 417 secret rules | ~14 ms |
| loading a 26 MB binary | ~7 ms |
| process spawn and Go runtime init | ~5 ms |

Detection was 1% of the bill. The other 99% was setup, thrown away and redone
on the next tool call. `--fast` reached 14.1 ms by not compiling the secret
rules, which is to say by not looking for credentials — buying latency with
coverage.

A profile settled where the remaining cost was: package `init` across the whole
dependency tree totals under 2 ms, while a trivial Go binary on the same machine
spawns in 5.4 ms against this one's 12.2 ms. The gap is the binary's size, not
work it performs.

## Decision

**A daemon holds the compiled rule set.** `vedei daemon` listens on a Unix
socket and answers redaction requests. The rules are compiled once.

**A separate client binary speaks to it.** `vedei-hook` is 5 MB against
`vedei`'s 26 MB, because it imports the socket client and nothing else. It
detects nothing itself.

**The socket is Unix-domain only, mode 0600.** There is no TCP mode and there
should never be one: everything crossing it is text that was just judged
sensitive. Where vedei creates the socket's directory it is 0700; where the
directory already existed it is left alone and refused if it is world-writable
without the sticky bit, because chmod on a shared directory is not vedei's
call to make.

**Nothing requires the daemon.** Every caller falls back to scanning
in-process, per ADR-005. A daemon that is down costs milliseconds, not a
broken session.

Measured result, p95 over 110 calls:

| configuration | p95 |
| --- | ---: |
| `vedei-hook` + daemon | **8.4 ms** |
| `vedei hook` + daemon | 15.2 ms |
| `vedei hook --fast` | 14.1 ms |
| `vedei hook` | 28.9 ms |
| `vedei-hook`, no daemon | 36.3 ms |

The budget is met, and without trading away credential detection.

## Consequences

**Two binaries to install instead of one.** The cost is real: the split is the
only reason the client loads in 1 ms, but it is one more thing to explain and
one more thing to keep in step.

**The worst configuration is now reachable by accident.** `vedei-hook` with no
daemon is 36.3 ms — slower than `vedei hook` alone, because it spawns a second
process to do the work. Anyone who will not run a daemon should configure
`vedei hook` directly, and the hook docs lead with that.

**A long-lived process is a thing to reason about.** It holds no state beyond
the compiled rules, logs failures and never requests, and `--idle-timeout`
exists for people who would rather it not sit there. It still widens the
surface compared to a process that exits.

**Shutdown had to be made real.** Closing the listener does not close accepted
connections, so a client holding one idle kept the daemon alive through
SIGTERM until each connection was closed explicitly on cancellation.

**Two numbers are now load-bearing in the docs.** 8.4 ms and 28.9 ms are
machine-specific. The test that guards them asserts the ratio between the two
paths, not the absolute figures, because CI runs on shared hardware where
milliseconds are noise.
