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
go install github.com/mkmuniz/nadzor/cmd/nadzor-hook@latest
```

Two binaries, because the split is what makes the hook fast:

- **`nadzor`** carries the whole rule set — 417 secret rules and the
  dependency tree behind them, 26 MB. It is the CLI, and it runs the daemon.
- **`nadzor-hook`** is 5 MB and detects nothing. It forwards the text to the
  daemon over a Unix socket, which is why it loads in about 1 ms instead of 7.

Then start the daemon and follow the directory for your agent:

```bash
nadzor daemon            # or install the service file below
nadzor daemon status     # 0 when it answers, 1 when it does not
```

- [`claude-code/`](claude-code/)
- [`codex/`](codex/)

Nothing requires the daemon. Without it `nadzor-hook` runs the full binary
instead, which is correct and slower; see the table below.

## Cost

Measured on an M-series Mac, p95 over 110 calls on one tool result:

| what you configure | p95 | detects |
| --- | --- | --- |
| `nadzor-hook` + daemon | **8.4 ms** | everything |
| `nadzor hook` + daemon | 15.2 ms | everything |
| `nadzor hook --fast` | 14.1 ms | Brazilian data only |
| `nadzor hook` | 28.9 ms | everything |
| `nadzor-hook`, no daemon | 36.3 ms | everything |

Detection itself is 258µs. Everything above it is process startup and rule
compilation, which is the whole reason the daemon exists.

Two things to read off that table:

- **`nadzor-hook` without a daemon is the slowest option**, because it starts
  a second process to do the work. If you will not run a daemon, configure
  `nadzor hook` directly.
- `--fast` and the daemon cost about the same, but `--fast` buys the speed by
  not looking for credentials. The daemon does not give anything up.

Whether 8 ms or 29 ms matters depends on the tool being wrapped: noticeable
against reading a small file, invisible against anything touching the network.

## Running the daemon as a service

The socket is created mode `0600` inside a `0700` directory and is
Unix-domain only — there is no TCP mode, because everything crossing it is
text that was just judged sensitive.

**macOS (launchd).** Copy [`launchd/br.dev.nadzor.daemon.plist`](launchd/br.dev.nadzor.daemon.plist)
to `~/Library/LaunchAgents/`, fix the path to your binary, then:

```bash
launchctl load -w ~/Library/LaunchAgents/br.dev.nadzor.daemon.plist
nadzor daemon status
```

**Linux (systemd user unit).** Copy [`systemd/nadzor.service`](systemd/nadzor.service)
to `~/.config/systemd/user/`, then:

```bash
systemctl --user enable --now nadzor
nadzor daemon status
```

Pass `--idle-timeout 8h` if you would rather it exit when unused. Socket path
resolution, in order: `NADZOR_SOCKET`, `$XDG_RUNTIME_DIR/nadzor/sock`,
`~/.nadzor/sock`.
