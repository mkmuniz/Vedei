package main

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/mkmuniz/vedei/detect"
	"github.com/mkmuniz/vedei/internal/hookevent"
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

For the lowest latency, configure vedei-hook instead of this command and run
"vedei daemon": that pair costs about 6 ms against 29 ms here, because this
binary carries the whole rule set and is loaded from scratch on every call.
This command is what vedei-hook falls back to when no daemon answers, and it
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
			if _, err := os.Stdout.Write(runHook(cmd.Context(), input, opts)); err != nil {
				return err
			}
			return nil
		},
	}

	bindRedactFlags(cmd, &opts, true)
	return cmd
}

// runHook rewrites one hook event. Reports go to stderr, which the agent shows
// the user but does not send to the model, so a person can see what was held
// back.
func runHook(ctx context.Context, input []byte, opts redactOpts) []byte {
	return hookevent.Rewrite(input, func(text string) (string, bool) {
		res := redact(ctx, text, detect.Metadata{Source: "agent-hook"}, opts)
		if res.Degraded {
			if opts.failClosed {
				fmt.Fprintf(os.Stderr, "vedei: output withheld, detection failed: %v\n", res.Err)
				return hookevent.Withheld, true
			}
			return "", false
		}
		if !res.Redacted {
			return "", false
		}
		for _, f := range res.Findings {
			fmt.Fprintf(os.Stderr, "vedei: redacted %s\n", f.Type)
		}
		return res.Text, true
	})
}
