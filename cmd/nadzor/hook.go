package main

import (
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/mkmuniz/nadzor/detect"
	"github.com/mkmuniz/nadzor/internal/hookevent"
)

func newHookCmd() *cobra.Command {
	var opts redactOpts

	cmd := &cobra.Command{
		Use:   "hook",
		Short: "Redact a coding agent's tool result before it reaches the model",
		Long: `Reads a hook event as JSON on stdin, redacts the tool output inside it,
and writes the event back on stdout.

Install it as a PostToolUse hook so that when the agent runs "cat .env", the
model receives the output with credentials masked. See hooks/ for the
per-agent configuration.

For the lowest latency, configure nadzor-hook instead of this command and run
"nadzor daemon": that pair costs about 6 ms against 29 ms here, because this
binary carries the whole rule set and is loaded from scratch on every call.
This command is what nadzor-hook falls back to when no daemon answers, and it
works on its own.

Everything here is fail-open: an unrecognized event, a detection failure or
malformed JSON all result in the original event being written back
unchanged. A hook that blocks is worse than a hook that misses something.`,
		Args:          cobra.NoArgs,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			input, err := io.ReadAll(os.Stdin)
			if err != nil {
				return nil
			}
			out := hookevent.Rewrite(input, func(text string) (string, bool) {
				res := redact(cmd.Context(), text, detect.Metadata{Source: "agent-hook"}, opts)
				if res.Degraded || !res.Redacted {
					return "", false
				}
				// Report on stderr, which the agent shows the user but does
				// not send to the model, so a person can see what was held back.
				for _, f := range res.Findings {
					fmt.Fprintf(os.Stderr, "nadzor: redacted %s\n", f.Type)
				}
				return res.Text, true
			})
			if _, err := os.Stdout.Write(out); err != nil {
				return err
			}
			return nil
		},
	}

	bindRedactFlags(cmd, &opts, true)
	return cmd
}
