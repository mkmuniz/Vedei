package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var version = "dev"

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "nadzor",
		Short: "Find and validate Brazilian sensitive data and leaked secrets",
		Long: `nadzor finds Brazilian sensitive data and leaked credentials, and
validates them offline with check digits before they reach your logs, your
CI, or your AI agent's context.

Exit codes: 0 clean, 3 findings, 1 error.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       version,
	}

	root.AddCommand(newStreamCmd(), newTranscriptCmd(), newHookCmd())
	return root
}

func main() {
	if err := newRootCmd().Execute(); err != nil {
		var coder exitCoder
		if errors.As(err, &coder) {
			os.Exit(coder.ExitCode())
		}
		fmt.Fprintln(os.Stderr, "nadzor:", err)
		os.Exit(exitError)
	}
}

// exitCoder lets a command choose its exit code without calling os.Exit
// itself, which would make it untestable.
type exitCoder interface {
	error
	ExitCode() int
}

type findingsError struct{ n int }

func (e findingsError) Error() string { return fmt.Sprintf("%d finding(s)", e.n) }
func (e findingsError) ExitCode() int { return exitFindings }
