package main_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

const (
	testCPF  = "529.982.247-25"
	testFile = "hook event"
)

// bins locates the built binaries, skipping the suite when they are missing:
// these tests are about the pair of processes, not about the packages.
func bins(t *testing.T) (vedei, hook string) {
	t.Helper()
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatalf("Abs: %v", err)
	}
	vedei = filepath.Join(root, "bin", "vedei")
	hook = filepath.Join(root, "bin", "vedei-hook")
	for _, b := range []string{vedei, hook} {
		if _, err := os.Stat(b); err != nil {
			t.Skip("binaries not built; run make build")
		}
	}
	return vedei, hook
}

// shortSocket returns a socket path under the length the kernel allows, which
// t.TempDir can exceed because it embeds the test name.
func shortSocket(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "nz")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, "sock")
}

// startDaemon runs the real daemon process and waits for it to answer.
func startDaemon(t *testing.T, vedei, socket string) {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, vedei, "daemon", "--socket", socket) //nolint:gosec // built binary
	var logs bytes.Buffer
	cmd.Stderr = &logs
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatalf("starting the daemon: %v", err)
	}
	t.Cleanup(func() {
		cancel()
		_ = cmd.Wait()
		if t.Failed() {
			t.Logf("daemon log:\n%s", logs.String())
		}
	})

	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		out, err := exec.CommandContext(ctx, vedei, "daemon", "status", "--socket", socket).CombinedOutput() //nolint:gosec // built binary
		if err == nil {
			return
		}
		_ = out
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("the daemon never answered on %s", socket)
}

func runHook(t *testing.T, hook, input string, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, hook, args...) //nolint:gosec // built binary
	cmd.Stdin = strings.NewReader(input)
	var out bytes.Buffer
	cmd.Stdout = &out
	_ = cmd.Run()
	return out.String()
}

func event(text string) string {
	b, err := json.Marshal(map[string]string{"tool_name": "Read", "tool_response": text})
	if err != nil {
		panic(err)
	}
	return string(b)
}

func TestHookClient_RedactsThroughTheDaemon(t *testing.T) {
	vedei, hook := bins(t)
	socket := shortSocket(t)
	startDaemon(t, vedei, socket)

	out := runHook(t, hook, event("cpf "+testCPF+" fim"), "--socket", socket)
	if strings.Contains(out, testCPF) {
		t.Fatalf("the value reached the model: %s", out)
	}
	if !strings.Contains(out, "vedei: cpf redacted") {
		t.Fatalf("no redaction marker: %s", out)
	}

	var ev map[string]any
	if err := json.Unmarshal([]byte(out), &ev); err != nil {
		t.Fatalf("the event is not valid JSON: %v\n%s", err, out)
	}
	if ev["tool_name"] != "Read" {
		t.Errorf("tool_name was lost: %v", ev["tool_name"])
	}
}

func TestHookClient_CleanEventIsUnchanged(t *testing.T) {
	vedei, hook := bins(t)
	socket := shortSocket(t)
	startDaemon(t, vedei, socket)

	in := event("nada sensivel aqui")
	if out := runHook(t, hook, in, "--socket", socket); out != in {
		t.Errorf("a clean event was rewritten:\n got %s\nwant %s", out, in)
	}
}

// Without a daemon the client execs the full binary. The redaction still has
// to happen — slower, but not skipped.
func TestHookClient_FallsBackToTheFullBinary(t *testing.T) {
	vedei, hook := bins(t)

	out := runHook(t, hook, event("cpf "+testCPF),
		"--socket", shortSocket(t), "--fallback", vedei)
	if strings.Contains(out, testCPF) {
		t.Fatalf("the fallback did not redact: %s", out)
	}
}

// No daemon and no fallback is the worst case, and it still must not break the
// session: the event goes back exactly as it arrived.
func TestHookClient_PassesThroughWithNothingAvailable(t *testing.T) {
	_, hook := bins(t)

	in := event("cpf " + testCPF)
	out := runHook(t, hook, in, "--socket", shortSocket(t), "--fallback", "-")
	if out != in {
		t.Errorf("the event was altered with no engine available:\n got %s\nwant %s", out, in)
	}
}

func TestHookClient_FailsOpenOnMalformedInput(t *testing.T) {
	vedei, hook := bins(t)
	socket := shortSocket(t)
	startDaemon(t, vedei, socket)

	for _, in := range []string{`{not json`, `["a"]`, `{"other":"x"}`, `{"tool_response":{"a":1}}`, ``} {
		if out := runHook(t, hook, in, "--socket", socket); out != in {
			t.Errorf("input %q came back as %q", in, out)
		}
	}
}

// TestHookLatency is the M3 exit criterion, measured rather than assumed.
//
// It reports and does not assert: the budget is about a developer's machine,
// and CI runs on shared hardware where any absolute figure in milliseconds is
// noise. The ratio between the two paths is what it checks, because that is
// the part that is a property of the code.
func TestHookLatency(t *testing.T) {
	if testing.Short() {
		t.Skip("measures process latency; skipped under -short")
	}
	vedei, hook := bins(t)
	socket := shortSocket(t)
	startDaemon(t, vedei, socket)

	in := event("cpf " + testCPF + " e uma chave AKIAIOSFODNN7EXAMPLE fim")
	const runs = 40

	ctx := context.Background()

	measure := func(bin string, args ...string) time.Duration {
		samples := make([]time.Duration, 0, runs)
		for i := range runs {
			start := time.Now()
			cmd := exec.CommandContext(ctx, bin, args...) //nolint:gosec // built binary
			cmd.Stdin = strings.NewReader(in)
			_ = cmd.Run()
			if i < 5 {
				continue // page cache and dynamic linking
			}
			samples = append(samples, time.Since(start))
		}
		sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
		return samples[int(float64(len(samples))*0.95)]
	}

	viaDaemon := measure(hook, "--socket", socket)
	inProcess := measure(vedei, "hook", "--no-daemon")

	t.Logf("p95 vedei-hook via daemon: %v", viaDaemon.Round(10*time.Microsecond))
	t.Logf("p95 vedei hook in-process: %v", inProcess.Round(10*time.Microsecond))

	if viaDaemon >= inProcess {
		t.Errorf("the daemon path is not faster: %v via daemon, %v in-process", viaDaemon, inProcess)
	}
}
