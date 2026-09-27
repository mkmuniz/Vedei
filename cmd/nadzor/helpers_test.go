package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestFindOutput(t *testing.T) {
	cases := []struct {
		name      string
		event     string
		wantField string
		wantText  string
		wantOK    bool
	}{
		{"claude code", `{"tool_response":"saida"}`, "tool_response", "saida", true},
		{"codex", `{"output":"saida"}`, "output", "saida", true},
		{"no known field", `{"other":"saida"}`, "", "", false},
		// A structured result is left alone rather than guessed at.
		{"structured", `{"tool_response":{"a":1}}`, "", "", false},
		{"empty object", `{}`, "", "", false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var ev map[string]json.RawMessage
			if err := json.Unmarshal([]byte(c.event), &ev); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			field, text, ok := findOutput(ev)
			if field != c.wantField || text != c.wantText || ok != c.wantOK {
				t.Errorf("findOutput() = (%q, %q, %v), want (%q, %q, %v)",
					field, text, ok, c.wantField, c.wantText, c.wantOK)
			}
		})
	}
}

// Fields are tried in order so the agent's own name for the output wins over
// a generic one when an event carries both.
func TestFindOutput_PrefersTheMostSpecificField(t *testing.T) {
	var ev map[string]json.RawMessage
	if err := json.Unmarshal([]byte(`{"result":"generic","tool_response":"specific"}`), &ev); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	field, text, _ := findOutput(ev)
	if field != "tool_response" || text != "specific" {
		t.Errorf("got %q = %q, want tool_response", field, text)
	}
}

func TestTruncate(t *testing.T) {
	cases := map[string]string{
		"short":                              "short",
		"exactly-ten-chars-here-and-more-xx": "...-chars-here-and-more-xx",
	}
	for in, want := range cases {
		if got := truncate(in, 26); got != want {
			t.Errorf("truncate(%q) = %q, want %q", in, got, want)
		}
	}
	// The tail survives, because that is what a reader matches against.
	long := strings.Repeat("x", 60) + "ab"
	if got := truncate(long, 20); !strings.HasSuffix(got, "ab") || len(got) != 20 {
		t.Errorf("truncate kept the wrong end or length: %q", got)
	}
}

func TestFindingsError(t *testing.T) {
	e := findingsError{n: 3}
	if e.ExitCode() != exitFindings {
		t.Errorf("ExitCode = %d, want %d", e.ExitCode(), exitFindings)
	}
	if !strings.Contains(e.Error(), "3") {
		t.Errorf("Error() should name the count: %q", e.Error())
	}
}

// The three codes must stay distinct: conflating "found something" with
// "the scan broke" is the bug that makes a failed CI run look clean.
func TestExitCodesAreDistinct(t *testing.T) {
	seen := map[int]bool{}
	for _, c := range []int{exitClean, exitError, exitFindings} {
		if seen[c] {
			t.Fatalf("exit code %d is used twice", c)
		}
		seen[c] = true
	}
}
