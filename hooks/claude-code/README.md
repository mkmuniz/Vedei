# Claude Code

## Install

```bash
go install github.com/mkmuniz/vedei/cmd/vedei@latest
go install github.com/mkmuniz/vedei/cmd/vedei-hook@latest
vedei daemon &            # or install the service file in ../launchd/
```

Add to `~/.claude/settings.json`:

```json
{
  "hooks": {
    "PostToolUse": [
      {
        "matcher": "Bash|Read|Grep|Glob",
        "hooks": [
          { "type": "command", "command": "vedei-hook", "timeout": 5 }
        ]
      }
    ]
  }
}
```

Start a new session. Nothing else changes.

If you would rather not run a daemon, use `"command": "vedei hook"` instead.
That is slower — see the table — but it is a single binary and no service.

## Verify

```bash
echo '{"tool_response":"cpf 529.982.247-25"}' | vedei-hook
```

```json
{"tool_response":"cpf ***.***.***-25 [vedei: cpf redacted]"}
```

Then, in a real session: put a valid CPF and a credential in a file and ask
the agent to read it. The model receives them masked, and your terminal shows
what was withheld:

```
vedei: redacted stripe-access-token
vedei: redacted cpf
```

The report goes to stderr, which the agent shows you and does not send to the
model.

## Cost

Measured on an M-series Mac, p95 over 110 calls:

| what you configure | p95 | detects |
| --- | ---: | --- |
| `vedei-hook`, daemon running | **8.4 ms** | everything |
| `vedei hook`, daemon running | 15.2 ms | everything |
| `vedei hook --fast` | 14.1 ms | Brazilian data only |
| `vedei hook` | 28.9 ms | everything |
| `vedei-hook`, no daemon | 36.3 ms | everything |

Detection itself is 258µs. The rest is process startup and compiling 417
secret rules, which is why the daemon and the small client exist: the daemon
removes the compilation, and `vedei-hook` removes most of the startup by not
linking the rules at all.

`--fast` reaches a similar number by not looking for credentials. The daemon
gets there without giving anything up, so prefer it.

## Scope

The matcher covers the tools returning file and command output. Widen it to
`".*"` to cover everything, at the cost of running on results that cannot
contain anything.

## If something breaks

Every path is fail-open: malformed JSON, an unrecognized event shape, a
structured rather than textual result, a daemon that is down, or any detection
failure all return the event unchanged. Remove the block above and restart to
rule it out.

`vedei daemon status` says whether the daemon is answering. When it is not,
`vedei-hook` runs the full binary instead — correct, just slower.

## Regulated environments: `--fail-closed`

Fail-open is the right default for most people: a hook that breaks the session
gets uninstalled. It is the wrong trade where an unscanned CPF reaching a model
is a reportable incident. For those environments:

```json
{ "type": "command", "command": "vedei-hook --fail-closed", "timeout": 5 }
```

With the flag, when detection cannot run — the engine fails, the input is over
the size cap, or there is no daemon and no vedei binary to fall back to — the
tool output is replaced by a notice instead of being passed through:

```
[vedei: output withheld — detection could not run, and --fail-closed is set]
```

The agent loses that one result and can retry; the value never reaches the
model unscanned. Everything else is unchanged: a scan that runs still redacts,
and a clean result still passes. Two things stay fail-open even with the flag,
because there is no tool output in them to withhold: malformed JSON, and an
event shape vedei does not recognize.
