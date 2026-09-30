package hookevent_test

import (
	"encoding/json"
	"testing"

	"github.com/mkmuniz/vedei/internal/hookevent"
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
			field, text, ok := hookevent.Find(ev)
			if field != c.wantField || text != c.wantText || ok != c.wantOK {
				t.Errorf("hookevent.Find() = (%q, %q, %v), want (%q, %q, %v)",
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
	field, text, _ := hookevent.Find(ev)
	if field != "tool_response" || text != "specific" {
		t.Errorf("got %q = %q, want tool_response", field, text)
	}
}

// Rewrite is the fail-open boundary: every one of these has to hand back the
// bytes it was given, because a hook that mangles or drops an event breaks the
// session it was meant to protect.
func TestRewrite_PassesThroughOnEveryFailure(t *testing.T) {
	always := func(string) (string, bool) { return "REDACTED", true }
	never := func(string) (string, bool) { return "", false }

	cases := []struct {
		name  string
		input string
		fn    hookevent.Redactor
	}{
		{"malformed JSON", `{not json`, always},
		{"a JSON array", `["a","b"]`, always},
		{"no known field", `{"other":"saida"}`, always},
		{"a structured result", `{"tool_response":{"a":1}}`, always},
		{"an empty output", `{"tool_response":""}`, always},
		{"a redactor that declines", `{"tool_response":"saida"}`, never},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := string(hookevent.Rewrite([]byte(c.input), c.fn)); got != c.input {
				t.Errorf("Rewrite() = %q, want the input unchanged", got)
			}
		})
	}
}

func TestRewrite_ReplacesTheOutput(t *testing.T) {
	in := `{"tool_name":"Read","tool_response":"cpf 529.982.247-25"}`
	out := hookevent.Rewrite([]byte(in), func(text string) (string, bool) {
		if text != "cpf 529.982.247-25" {
			t.Fatalf("the redactor saw %q", text)
		}
		return "cpf ***", true
	})

	var ev map[string]any
	if err := json.Unmarshal(out, &ev); err != nil {
		t.Fatalf("the rewritten event is not JSON: %v", err)
	}
	if ev["tool_response"] != "cpf ***" {
		t.Errorf("tool_response = %v", ev["tool_response"])
	}
	// The other fields are the agent's, not ours to drop.
	if ev["tool_name"] != "Read" {
		t.Errorf("tool_name was lost: %v", ev["tool_name"])
	}
}

// An empty input is what a hook receives when the agent hands it nothing.
func TestRewrite_EmptyInput(t *testing.T) {
	if got := hookevent.Rewrite(nil, func(string) (string, bool) { return "x", true }); len(got) != 0 {
		t.Errorf("Rewrite(nil) = %q", got)
	}
}
