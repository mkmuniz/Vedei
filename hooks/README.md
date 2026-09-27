# Agent hooks

These keep secrets and Brazilian personal data out of a coding agent's
context. When the agent runs `cat .env`, the output is redacted before the
model ever sees it.

## Why this is needed

No provider does this. Claude Code reads `.env` files into context even when
`CLAUDE.md` forbids it, and the session log keeps every tool result in
plaintext with no rotation. All three are open issues in its own tracker:
[#44868](https://github.com/anthropics/claude-code/issues/44868),
[#50014](https://github.com/anthropics/claude-code/issues/50014),
[#95680](https://github.com/anthropics/claude-code/issues/95680).

"We do not train on your data" is not "your data did not reach us". It
transits, it sits in the context window, and it stays on your disk.

## What it does not do

- It does not stop you pasting a secret into a prompt yourself.
- It does not redact what is already in your transcripts. Use
  `nadzor transcript scan` for that.
- It only covers what the agent obtains through a tool. A secret the model
  produces from its own memory is out of scope.
- Detection is not complete. Assume it misses things.

## Install

```bash
go install github.com/mkmuniz/nadzor/cmd/nadzor@latest
```

Then follow the directory for your agent:

- [`claude-code/`](claude-code/)
- [`codex/`](codex/)

## Cost

Detection itself costs 258µs on a typical tool result. The hook costs
**27.9 ms p50**, because each call is a fresh process: about 12 ms of
startup and 14 ms compiling the secret rule set.

`nadzor hook --fast` skips those rules and runs in 13.4 ms, detecting
Brazilian data but not credentials. A daemon that keeps the rules compiled
between calls would remove both costs and is not built yet.

Whether that matters depends on the tool being wrapped: noticeable against
reading a small file, invisible against anything touching the network.
