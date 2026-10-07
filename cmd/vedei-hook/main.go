// Command vedei-hook is the agent hook, kept small on purpose.
//
// The full vedei binary carries several hundred compiled secret rules and the
// dependency tree behind them, which is 26 MB to load before any work starts —
// about 7 ms of the 13 ms a hook call costs even when a daemon does the
// detection. This binary imports only the socket client, so it loads in ~1 ms,
// and the whole call lands near 6 ms.
//
// It never detects anything itself. With a daemon listening it forwards the
// text; without one it hands the event to "vedei hook", paying the full cost
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

	"github.com/mkmuniz/vedei/daemon"
	"github.com/mkmuniz/vedei/detect"
	"github.com/mkmuniz/vedei/internal/hookevent"
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
	fallback := flag.String("fallback", "", `vedei binary to fall back to, or "" to look for one beside this binary; "-" to disable`)
	failClosed := flag.Bool("fail-closed", false,
		"when detection cannot run, withhold the tool output instead of passing it through unscanned")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println("vedei-hook", version)
		return
	}

	input, err := io.ReadAll(os.Stdin)
	if err != nil {
		return // nothing to write back
	}

	out, ok := viaDaemon(context.Background(), input, *socket, *timeout, *failClosed)
	if !ok {
		out = viaFallback(input, *fallback, *fallbackTimeout, *failClosed)
	}
	_, _ = os.Stdout.Write(out)
}

// viaDaemon rewrites the event through the daemon, reporting whether it was
// able to. A false means the daemon could not be reached or could not answer;
// it does not mean the event was clean.
func viaDaemon(ctx context.Context, input []byte, socket string, timeout time.Duration, failClosed bool) ([]byte, bool) {
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
		if resp.Degraded && failClosed {
			fmt.Fprintln(os.Stderr, "vedei: output withheld, the daemon could not scan it")
			return hookevent.Withheld, true
		}
		if resp.Degraded || !resp.Redacted {
			return "", false
		}
		for _, f := range resp.Findings {
			fmt.Fprintf(os.Stderr, "vedei: redacted %s\n", f.Type)
		}
		return resp.Text, true
	})
	return out, served
}

// viaFallback hands the event to the full binary. On any failure — no binary,
// a non-zero exit, empty output — the original event is returned.
func viaFallback(input []byte, override string, timeout time.Duration, failClosed bool) []byte {
	// Every way this function gives up returns the same thing: the input as it
	// arrived, or — under --fail-closed — the input with its output withheld.
	giveUp := func() []byte {
		if failClosed {
			return hookevent.Withhold(input)
		}
		return input
	}

	bin, args := resolveFallback(override)
	if bin == "" {
		if failClosed {
			fmt.Fprintln(os.Stderr, "vedei: no daemon and no vedei binary found; output withheld")
		} else {
			fmt.Fprintln(os.Stderr, "vedei: no daemon and no vedei binary found; event passed through unredacted")
		}
		return giveUp()
	}
	// The full binary is told to fail closed too, so a fallback that cannot
	// scan withholds rather than passing the output through.
	if failClosed {
		args = append(args, "--fail-closed")
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, bin, args...) //#nosec G204 -- resolved from --fallback, VEDEI_BIN, or a vedei beside this binary; anyone who can set those can already run anything as this user
	cmd.Stdin = bytes.NewReader(input)
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err != nil || len(out) == 0 {
		return giveUp()
	}
	return out
}

// resolveFallback picks the vedei binary to fall back to: the --fallback flag,
// then VEDEI_BIN, then a vedei sitting beside this binary, then one on PATH.
// Every source is run the same way, as "vedei hook --no-daemon".
//
// --fallback used to be run with no arguments at all, which made vedei print
// its help — and the help text was written back to the agent in place of the
// tool's output. A path given here is a vedei binary like any other source.
//
// The sibling is tried before PATH so an installation is self-contained: the
// pair is built and shipped together, and a different vedei earlier on PATH
// should not quietly take over.
func resolveFallback(override string) (bin string, args []string) {
	hookArgs := []string{"hook", "--no-daemon"}
	switch override {
	case "-":
		return "", nil
	case "":
	default:
		return override, hookArgs
	}

	if env := os.Getenv("VEDEI_BIN"); env != "" {
		return env, hookArgs
	}
	if self, err := os.Executable(); err == nil {
		sibling := filepath.Join(filepath.Dir(self), "vedei")
		if st, err := os.Stat(sibling); err == nil && !st.IsDir() {
			return sibling, hookArgs
		}
	}
	if found, err := exec.LookPath("vedei"); err == nil {
		return found, hookArgs
	}
	return "", nil
}
