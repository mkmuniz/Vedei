package main

import (
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/mkmuniz/nadzor/detect"
)

func newStreamCmd() *cobra.Command {
	var (
		opts  redactOpts
		quiet bool
	)

	cmd := &cobra.Command{
		Use:   "stream",
		Short: "Redact sensitive data from stdin to stdout",
		Long: `Reads stdin, writes it to stdout with every detected value replaced,
and reports what it found on stderr.

This is the command an agent hook runs on a tool result, so it is fail-open:
if detection fails the text passes through unchanged and the failure is
reported on stderr. Breaking your session is worse than missing a redaction.

A listening daemon answers the request, skipping the cost of compiling the
rule set; without one the work happens in-process.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			content, err := readInput(cmd.InOrStdin(), opts.maxInput)
			if err != nil {
				return err
			}

			res := redact(cmd.Context(), string(content), detect.Metadata{Source: "stdin"}, opts)
			if _, err := os.Stdout.WriteString(res.Text); err != nil {
				return err
			}

			if res.Degraded && !quiet {
				fmt.Fprintf(os.Stderr, "nadzor: passed through unredacted: %v\n", res.Err)
			}
			if len(res.Findings) == 0 {
				return nil
			}
			if !quiet {
				for _, f := range res.Findings {
					fmt.Fprintf(os.Stderr, "nadzor: redacted %s (%s)\n", f.Type, f.Confidence)
				}
			}
			return findingsError{n: len(res.Findings)}
		},
	}

	cmd.Flags().IntVar(&opts.maxInput, "max-input", 8<<20,
		"pass input larger than this through unscanned (0 for no limit)")
	cmd.Flags().BoolVarP(&quiet, "quiet", "q", false, "suppress the report on stderr")
	bindRedactFlags(cmd, &opts, true)
	return cmd
}

// readInput reads all of r, reading one byte past the cap so the processor can
// tell a capped input from one that merely fills it.
func readInput(r io.Reader, max int) ([]byte, error) {
	if max > 0 {
		r = io.LimitReader(r, int64(max)+1)
	}
	content, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("reading stdin: %w", err)
	}
	return content, nil
}
