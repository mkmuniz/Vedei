package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"
)

const testCPF = "529.982.247-25"

// runHookBinary exercises the command the way an agent does: a fresh
// process, JSON on stdin, JSON on stdout.
func runHookBinary(t *testing.T, input string, args ...string) string {
	t.Helper()
	bin := os.Getenv("NADZOR_BIN")
	if bin == "" {
		bin = "../../bin/nadzor"
	}
	if _, err := os.Stat(bin); err != nil {
		t.Skip("binary not built; run make build")
	}

	cmd := exec.Command(bin, append([]string{"hook"}, args...)...) //nolint:gosec // fixed path
	cmd.Stdin = strings.NewReader(input)
	var out bytes.Buffer
	cmd.Stdout = &out
	_ = cmd.Run()
	return out.String()
}

func TestHook_RedactsToolOutput(t *testing.T) {
	in := `{"tool_name":"Read","tool_response":"cpf ` + testCPF + ` fim"}`
	out := runHookBinary(t, in)

	if strings.Contains(out, testCPF) {
		t.Fatalf("the value reached the model: %s", out)
	}
	var event map[string]any
	if err := json.Unmarshal([]byte(out), &event); err != nil {
		t.Fatalf("the hook emitted invalid JSON: %s", out)
	}
	if event["tool_name"] != "Read" {
		t.Errorf("other fields must survive: %v", event)
	}
}

// Every failure mode must return the event untouched. A hook that blocks is
// worse than a hook that misses something.
func TestHook_FailsOpen(t *testing.T) {
	cases := map[string]string{
		"malformed JSON":    "this is not json at all",
		"no output field":   `{"tool_name":"Read","other":"value"}`,
		"structured output": `{"tool_response":{"nested":"object"}}`,
		"empty output":      `{"tool_response":""}`,
		"empty input":       "",
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			if out := runHookBinary(t, in); out != in {
				t.Errorf("event was altered\n in: %q\nout: %q", in, out)
			}
		})
	}
}

func TestHook_CleanOutputPassesThroughByteForByte(t *testing.T) {
	in := `{"tool_name":"Read","tool_response":"nada sensivel nesta saida"}`
	if out := runHookBinary(t, in); out != in {
		t.Errorf("clean event was rewritten\n in: %q\nout: %q", in, out)
	}
}

func TestHook_RecognizesEachAgentsField(t *testing.T) {
	// Agents differ and change; the event is matched on any known field.
	for _, field := range []string{"tool_response", "tool_result", "output", "tool_output", "result"} {
		t.Run(field, func(t *testing.T) {
			in := `{"` + field + `":"cpf ` + testCPF + `"}`
			out := runHookBinary(t, in)
			if strings.Contains(out, testCPF) {
				t.Errorf("field %s was not redacted: %s", field, out)
			}
		})
	}
}

func TestHook_FastSkipsSecretsButKeepsBrazilianData(t *testing.T) {
	in := `{"tool_response":"cpf ` + testCPF + `"}`
	out := runHookBinary(t, in, "--fast")
	if strings.Contains(out, testCPF) {
		t.Errorf("--fast must still redact Brazilian data: %s", out)
	}
}
