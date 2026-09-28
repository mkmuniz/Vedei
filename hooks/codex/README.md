# Codex

```bash
go install github.com/mkmuniz/nadzor/cmd/nadzor@latest
go install github.com/mkmuniz/nadzor/cmd/nadzor-hook@latest
nadzor daemon &
```

In `~/.codex/config.toml`:

```toml
[[hooks]]
event = "post_tool_use"
command = "nadzor-hook"
timeout_ms = 5000
```

Both commands read the output field under any of `tool_response`,
`tool_result`, `output`, `tool_output` or `result`, so it works with either
agent and survives a field being renamed.

> Codex's hook interface is less settled than Claude Code's. If the event
> shape has changed, the hook passes it through untouched rather than
> corrupting it. Check detection itself with
> `echo '{"output":"cpf 529.982.247-25"}' | nadzor-hook`, and please open an
> issue.

See [the Claude Code notes](../claude-code/README.md) for the measured cost of
each configuration and the `--fast` trade-off; both apply here.
