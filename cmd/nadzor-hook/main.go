// Command nadzor-hook is the agent hook, kept small on purpose.
//
// The full nadzor binary carries several hundred compiled secret rules and the
// dependency tree behind them, which is 26 MB to load before any work starts —
// about 7 ms of the 13 ms a hook call costs even when a daemon does the
// detection. This binary imports only the socket client, so it loads in ~1 ms,
// and the whole call lands near 6 ms.
//
// It never detects anything itself. With a daemon listening it forwards the
// text; without one it hands the event to "nadzor hook", paying the full cost
// rather than silently skipping the redaction. Both paths are fail-open: on
// any failure the event is written back byte for byte.
package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/mkmuniz/nadzor/daemon"
	"github.com/mkmuniz/nadzor/detect"
	"github.com/mkmuniz/nadzor/internal/hookevent"
)

var version = "dev"

func main() {
	socket := flag.String("socket", daemon.DefaultSocket(), "daemon socket to send the text to")
	timeout := flag.Duration("timeout", 2*time.Second, "give up on the daemon after this long")
	// The fallback spawns the full binary, which compiles the rule set. It is
	// bounded because a wedged child would otherwise hang the agent's session
	// for as long as it lived.
	fallbackTimeout := flag.Duration("fallback-timeout", 30*time.Second,
		"give up on the fallback command after this long")
	fallback := flag.String("fallback", "", `command to fall back to, or "" to look for nadzor beside this binary; "-" to disable`)
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println("nadzor-hook", version)
		return
	}

	input, err := io.ReadAll(os.Stdin)
	if err != nil {
		return // nothing to write back
	}

	out, ok := viaDaemon(context.Background(), input, *socket, *timeout)
	if !ok {
		out = viaFallback(input, *fallback, *fallbackTimeout)
	}
	_, _ = os.Stdout.Write(out)
}

// viaDaemon rewrites the event through the daemon, reporting whether it was
// able to. A false means the daemon could not be reached or could not answer;
// it does not mean the event was clean.
func viaDaemon(ctx context.Context, input []byte, socket string, timeout time.Duration) ([]byte, bool) {
	if socket == "" {
		return nil, false
	}
	c, err := daemon.Dial(ctx, socket, daemon.WithTimeout(timeout))
	if err != nil {
		return nil, false
	}
	defer func() { _ = c.Close() }()

	served := false
	out := hookevent.Rewrite(input, func(text string) (string, bool) {
		resp, err := c.Redact(ctx, text, detect.Metadata{Source: "agent-hook"})
		if err != nil {
			return "", false
		}
		// A degraded answer is the daemon's engine failing, not the daemon
		// being unreachable. Re-running it elsewhere would fail the same way,
		// so the event is served, unredacted.
		served = true
		if resp.Degraded || !resp.Redacted {
			return "", false
		}
		for _, f := range resp.Findings {
			fmt.Fprintf(os.Stderr, "nadzor: redacted %s\n", f.Type)
		}
		return resp.Text, true
	})
	return out, served
}

// viaFallback hands the event to the full binary. On any failure — no binary,
// a non-zero exit, empty output — the original event is returned.
func viaFallback(input []byte, override string, timeout time.Duration) []byte {
	bin, args := resolveFallback(override)
	if bin == "" {
		fmt.Fprintln(os.Stderr, "nadzor: no daemon and no nadzor binary found; event passed through unredacted")
		return input
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, bin, args...) //nolint:gosec // resolved from the flag or this binary's own directory
	cmd.Stdin = bytes.NewReader(input)
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err != nil || len(out) == 0 {
		return input
	}
	return out
}

// resolveFallback picks the command to fall back to: the --fallback flag, then
// NADZOR_BIN, then a nadzor sitting beside this binary, then one on PATH.
//
// The sibling is tried before PATH so an installation is self-contained: the
// pair is built and shipped together, and a different nadzor earlier on PATH
// should not quietly take over.
func resolveFallback(override string) (bin string, args []string) {
	switch override {
	case "-":
		return "", nil
	case "":
	default:
		return override, nil
	}

	if env := os.Getenv("NADZOR_BIN"); env != "" {
		return env, []string{"hook", "--no-daemon"}
	}
	if self, err := os.Executable(); err == nil {
		sibling := filepath.Join(filepath.Dir(self), "nadzor")
		if st, err := os.Stat(sibling); err == nil && !st.IsDir() {
			return sibling, []string{"hook", "--no-daemon"}
		}
	}
	if found, err := exec.LookPath("nadzor"); err == nil {
		return found, []string{"hook", "--no-daemon"}
	}
	return "", nil
}
