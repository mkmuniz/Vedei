package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
)

var version = "dev"

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "vedei",
		Short: "Find and validate Brazilian sensitive data and leaked secrets",
		Long: `vedei finds Brazilian sensitive data and leaked credentials, and
validates them offline with check digits before they reach your logs, your
CI, or your AI agent's context.

Exit codes: 0 clean, 3 findings, 1 error.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       version,
	}

	root.AddCommand(newScanCmd(), newGitCmd(), newDiffCmd(), newStreamCmd(),
		newTranscriptCmd(), newHookCmd(), newDaemonCmd())
	return root
}

func main() {
	// The daemon runs until it is stopped, so the process needs to hear
	// SIGINT and SIGTERM: the signal cancels the context, which closes the
	// listener and unlinks the socket instead of leaving a stale one behind.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := newRootCmd().ExecuteContext(ctx); err != nil {
		var coder exitCoder
		if errors.As(err, &coder) {
			os.Exit(coder.ExitCode())
		}
		fmt.Fprintln(os.Stderr, "vedei:", err)
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
