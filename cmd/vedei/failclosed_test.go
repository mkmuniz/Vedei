package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mkmuniz/vedei/internal/hookevent"
)

// degradedOpts makes detection fail on purpose: an input cap smaller than any
// event marks the scan degraded, the same state a panicking engine produces.
func degradedOpts(failClosed bool) redactOpts {
	return redactOpts{noDaemon: true, maxInput: 5, failClosed: failClosed}
}

// The default stays fail-open (ADR-005): a scan that could not run passes the
// event through unchanged, so the session keeps working.
func TestRunHook_FailOpenByDefault(t *testing.T) {
	in := []byte(`{"tool_name":"Read","tool_response":"cpf ` + testCPF + `"}`)
	if got := runHook(context.Background(), in, degradedOpts(false)); !bytes.Equal(got, in) {
		t.Errorf("fail-open altered the event:\n got %s\nwant %s", got, in)
	}
}

// --fail-closed is for the environments where an unscanned CPF reaching a
// model is a reportable incident: the output is withheld instead.
func TestRunHook_FailClosedWithholds(t *testing.T) {
	in := []byte(`{"tool_name":"Read","tool_response":"cpf ` + testCPF + `"}`)
	got := string(runHook(context.Background(), in, degradedOpts(true)))

	if strings.Contains(got, testCPF) {
		t.Fatalf("the unscanned value got through: %s", got)
	}
	if !strings.Contains(got, "output withheld") {
		t.Errorf("no withheld notice: %s", got)
	}
	if !strings.Contains(got, `"tool_name":"Read"`) {
		t.Errorf("the rest of the event was lost: %s", got)
	}
}

// --fail-closed changes only what happens when detection fails. A scan that
// runs and finds nothing still passes the text through.
func TestRunHook_FailClosedLeavesCleanTextAlone(t *testing.T) {
	in := []byte(`{"tool_response":"nada aqui"}`)
	opts := redactOpts{noDaemon: true, failClosed: true}
	if got := runHook(context.Background(), in, opts); !bytes.Equal(got, in) {
		t.Errorf("a clean event was altered: %s", got)
	}
}

// stream under --fail-closed writes the notice, none of the input, and exits
// with an error rather than reporting clean.
func TestStream_FailClosed(t *testing.T) {
	bin := os.Getenv("VEDEI_BIN")
	if bin == "" {
		bin = "../../bin/vedei"
	}
	if _, err := os.Stat(bin); err != nil {
		t.Skip("binary not built; run make build")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, bin, "stream", "--no-daemon", "--max-input", "5", "--fail-closed", //nolint:gosec // fixed path
		"--socket", filepath.Join(t.TempDir(), "absent.sock"))
	cmd.Stdin = strings.NewReader("cpf " + testCPF)
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()

	var exitErr *exec.ExitError
	if err == nil || !errors.As(err, &exitErr) || exitErr.ExitCode() != exitError {
		t.Fatalf("exit = %v, want %d", err, exitError)
	}
	if strings.Contains(out.String(), testCPF) {
		t.Fatalf("the unscanned value got through: %q", out.String())
	}
	if strings.TrimSpace(out.String()) != hookevent.Withheld {
		t.Errorf("stdout = %q, want only the withheld notice", out.String())
	}
}
