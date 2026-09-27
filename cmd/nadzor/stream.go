package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/mkmuniz/nadzor/detect"
	"github.com/mkmuniz/nadzor/engine"
	"github.com/mkmuniz/nadzor/stream"
)

func newStreamCmd() *cobra.Command {
	var (
		maxInput int
		quiet    bool
	)

	cmd := &cobra.Command{
		Use:   "stream",
		Short: "Redact sensitive data from stdin to stdout",
		Long: `Reads stdin, writes it to stdout with every detected value replaced,
and reports what it found on stderr.

This is the command an agent hook runs on a tool result, so it is fail-open:
if detection fails the text passes through unchanged and the failure is
reported on stderr. Breaking your session is worse than missing a redaction.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			p, err := stream.New(engine.Offline(), stream.WithMaxInput(maxInput))
			if err != nil {
				return err
			}

			res, err := p.Copy(cmd.Context(), os.Stdout, os.Stdin,
				detect.Metadata{Source: "stdin"})
			if err != nil {
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

	cmd.Flags().IntVar(&maxInput, "max-input", 8<<20,
		"pass input larger than this through unscanned (0 for no limit)")
	cmd.Flags().BoolVarP(&quiet, "quiet", "q", false, "suppress the report on stderr")
	return cmd
}
