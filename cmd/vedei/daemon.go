package main

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/mkmuniz/vedei/daemon"
	"github.com/mkmuniz/vedei/engine"
	"github.com/mkmuniz/vedei/stream"
)

func newDaemonCmd() *cobra.Command {
	var (
		socket   string
		idle     time.Duration
		maxInput int
		fast     bool
		quiet    bool
	)

	cmd := &cobra.Command{
		Use:   "daemon",
		Short: "Serve redaction requests over a Unix socket",
		Long: `Runs in the foreground, compiles the rule set once, and answers redaction
requests on a Unix socket.

It exists because of a measurement: a process that starts per tool call spends
about 12 ms on spawn and 14 ms compiling the secret rules to do 0.3 ms of
detection. The daemon pays that once, and "vedei hook" then costs a round
trip.

The socket is created mode 0600 inside a 0700 directory, and carries text that
was just judged sensitive, so it is Unix-domain only — there is no TCP mode.

Run it under launchd or systemd; see hooks/README.md. Nothing requires it:
every command that can use the daemon falls back to scanning in-process when
it is not there.`,
		Args:          cobra.NoArgs,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			eng := engine.Offline()
			if fast {
				eng = engine.BrazilianOnly()
			}
			p, err := stream.New(eng, stream.WithMaxInput(maxInput))
			if err != nil {
				return err
			}

			logw := cmd.ErrOrStderr()
			if quiet {
				logw = nopWriter{}
			}
			srv := daemon.NewServer(p, socket,
				daemon.WithIdleTimeout(idle),
				daemon.WithLog(logw),
			)
			if err := srv.Listen(cmd.Context()); err != nil {
				return err
			}
			if !quiet {
				_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "vedei daemon: listening on %s\n", srv.Addr())
			}
			return srv.Serve(cmd.Context())
		},
	}

	cmd.Flags().StringVar(&socket, "socket", daemon.DefaultSocket(), "socket path to listen on")
	cmd.Flags().DurationVar(&idle, "idle-timeout", 0,
		"exit after this long without a request (0 to run until stopped)")
	cmd.Flags().IntVar(&maxInput, "max-input", 8<<20,
		"pass input larger than this through unscanned (0 for no limit)")
	cmd.Flags().BoolVar(&fast, "fast", false,
		"serve only the Brazilian data rules, skipping the secret rule set")
	cmd.Flags().BoolVarP(&quiet, "quiet", "q", false, "do not report failures on stderr")

	cmd.AddCommand(newDaemonStatusCmd())
	return cmd
}

func newDaemonStatusCmd() *cobra.Command {
	var socket string

	cmd := &cobra.Command{
		Use:   "status",
		Short: "Report whether a daemon is listening",
		Long: `Connects to the socket and hangs up.

Exit codes here follow the rest of the CLI: 0 when a daemon answers, 1 when
none does. Nothing is broken when none does — every caller falls back to
scanning in-process.`,
		Args:          cobra.NoArgs,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if daemon.Available(cmd.Context(), socket) {
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "listening on %s\n", socket)
				return nil
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "no daemon on %s\n", socket)
			return errNoDaemon
		},
	}

	cmd.Flags().StringVar(&socket, "socket", daemon.DefaultSocket(), "socket path to check")
	return cmd
}

// errNoDaemon is a plain error rather than a findingsError: no daemon is an
// operational answer, not a detection result.
var errNoDaemon = daemonAbsentError{}

type daemonAbsentError struct{}

func (daemonAbsentError) Error() string { return "no daemon is listening" }
func (daemonAbsentError) ExitCode() int { return exitError }

type nopWriter struct{}

func (nopWriter) Write(p []byte) (int, error) { return len(p), nil }
