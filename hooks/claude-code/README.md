# Claude Code

## Install

```bash
go install github.com/mkmuniz/nadzor/cmd/nadzor@latest
```

Add to `~/.claude/settings.json`:

```json
{
  "hooks": {
    "PostToolUse": [
      {
        "matcher": "Bash|Read|Grep|Glob",
        "hooks": [
          { "type": "command", "command": "nadzor hook", "timeout": 5 }
        ]
      }
    ]
  }
}
```

Start a new session. Nothing else changes.

## Verify

```bash
echo '{"tool_response":"cpf 529.982.247-25"}' | nadzor hook
```

```json
{"tool_response":"cpf ***.***.***-25 [nadzor: cpf redacted]"}
```

Then, in a real session: put a valid CPF in a file and ask the agent to read
it. The model receives it masked, and your terminal shows what was withheld.

## Cost

Measured on an M-series Mac, per tool call:

| | p50 | p95 |
|---|---:|---:|
| `nadzor hook` | 27.9 ms | 28.8 ms |
| `nadzor hook --fast` | 13.4 ms | 14.1 ms |

Roughly 12 ms of that is process startup and 14 ms is compiling the secret
rule set. `--fast` skips those rules: Brazilian data is still detected,
credentials are not. Worth it only if you are scanning output that cannot
contain a credential.

Whether 28 ms matters depends on the tool. Against a `Read` of a small file
it is noticeable; against anything touching the network it disappears. A
daemon mode that keeps the rules compiled between calls is the fix and is
not built yet.

## Scope

The matcher covers the tools returning file and command output. Widen it to
`".*"` to cover everything, at the cost of running on results that cannot
contain anything.

## If something breaks

The hook is fail-open: malformed JSON, an unrecognized event shape, a
structured rather than textual result, or any detection failure all return
the event unchanged. Remove the block above and restart to rule it out.
