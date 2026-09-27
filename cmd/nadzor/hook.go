package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/mkmuniz/nadzor/detect"
	"github.com/mkmuniz/nadzor/engine"
	"github.com/mkmuniz/nadzor/stream"
)

// outputFields are the keys a tool result may arrive under, in the order
// they are tried. Agents differ and change; rather than one schema per
// agent, the event is decoded generically and the first matching key wins.
// An unrecognized event passes through untouched.
var outputFields = []string{
	"tool_response", // Claude Code
	"tool_result",
	"output", // Codex
	"tool_output",
	"result",
}

func newHookCmd() *cobra.Command {
	var fast bool

	cmd := &cobra.Command{
		Use:   "hook",
		Short: "Redact a coding agent's tool result before it reaches the model",
		Long: `Reads a hook event as JSON on stdin, redacts the tool output inside it,
and writes the event back on stdout.

Install it as a PostToolUse hook so that when the agent runs "cat .env", the
model receives the output with credentials masked. See hooks/ for the
per-agent configuration.

Everything here is fail-open: an unrecognized event, a detection failure or
malformed JSON all result in the original event being written back
unchanged. A hook that blocks is worse than a hook that misses something.`,
		Args:          cobra.NoArgs,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			input, err := io.ReadAll(os.Stdin)
			if err != nil {
				return passthrough(nil)
			}
			return runHook(cmd, input, fast)
		},
	}

	cmd.Flags().BoolVar(&fast, "fast", false,
		"skip the secret rule set, cutting startup at the cost of missing credentials")
	return cmd
}

func runHook(cmd *cobra.Command, input []byte, fast bool) error {
	var event map[string]json.RawMessage
	if err := json.Unmarshal(input, &event); err != nil {
		return passthrough(input)
	}

	field, text, ok := findOutput(event)
	if !ok || text == "" {
		return passthrough(input)
	}

	eng := engine.Offline()
	if fast {
		eng = engine.BrazilianOnly()
	}
	p, err := stream.New(eng)
	if err != nil {
		return passthrough(input)
	}

	redacted, res := p.Process(cmd.Context(), text, detect.Metadata{Source: "agent-hook"})
	if res.Degraded || !res.Redacted {
		return passthrough(input)
	}

	encoded, err := json.Marshal(redacted)
	if err != nil {
		return passthrough(input)
	}
	event[field] = encoded

	out, err := json.Marshal(event)
	if err != nil {
		return passthrough(input)
	}
	if _, err := os.Stdout.Write(out); err != nil {
		return err
	}

	// Report on stderr, which the agent shows the user but does not send to
	// the model, so a person can see what was withheld.
	for _, f := range res.Findings {
		fmt.Fprintf(os.Stderr, "nadzor: redacted %s\n", f.Type)
	}
	return nil
}

// findOutput returns the field holding the tool output, if the event has one.
func findOutput(event map[string]json.RawMessage) (field, text string, ok bool) {
	for _, k := range outputFields {
		raw, present := event[k]
		if !present {
			continue
		}
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			// The field exists but is not a string — a structured result.
			// Leave it alone rather than guess at its shape.
			continue
		}
		return k, s, true
	}
	return "", "", false
}

// passthrough writes the event back unchanged. It is the answer to every
// failure on this path.
func passthrough(input []byte) error {
	if len(input) > 0 {
		_, _ = os.Stdout.Write(input)
	}
	return nil
}
