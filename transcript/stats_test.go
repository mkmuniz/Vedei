package transcript_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/mkmuniz/vedei/detect"
	"github.com/mkmuniz/vedei/transcript"
)

func finding(engine, typ, fp, raw string) detect.Finding {
	return detect.Finding{
		Engine: engine, Type: typ, Fingerprint: fp, Raw: raw,
		Redacted:  "***" + raw[len(raw)-2:],
		Locations: []detect.Location{{Path: "/home/dev/.claude/projects/acme/session.jsonl", Line: 3}},
	}
}

func sampleSessions() []transcript.Session {
	cpf := finding("br", "cpf", "fp-cpf-1", "529.982.247-25")
	key := finding("secrets", "generic-api-key", "fp-key-1", "8f3kq9zLw2Xc7vB1nM4p")
	return []transcript.Session{
		{Path: "/home/dev/.claude/projects/acme/a.jsonl", Findings: []detect.Finding{cpf, key}},
		{Path: "/home/dev/.claude/projects/acme/b.jsonl", Findings: []detect.Finding{cpf}},
		{Path: "/home/dev/.claude/projects/acme/c.jsonl"},
	}
}

func TestSummarize(t *testing.T) {
	st := transcript.Summarize(sampleSessions(), 10)

	if st.Transcripts != 10 {
		t.Errorf("Transcripts = %d, want 10 (every file read, not only the dirty ones)", st.Transcripts)
	}
	if st.WithFinding != 2 {
		t.Errorf("WithFinding = %d, want 2", st.WithFinding)
	}
	if st.WithCredential != 1 || st.WithPersonalData != 2 {
		t.Errorf("WithCredential = %d, WithPersonalData = %d, want 1 and 2",
			st.WithCredential, st.WithPersonalData)
	}

	// One CPF in two transcripts: two transcripts, one distinct value.
	if got := st.ByType["cpf"]; got.Transcripts != 2 || got.Values != 1 {
		t.Errorf("cpf = %+v, want 2 transcripts and 1 value", got)
	}
	if got := st.ByType["generic-api-key"]; got.Transcripts != 1 || got.Values != 1 {
		t.Errorf("generic-api-key = %+v, want 1 and 1", got)
	}
}

// The property the whole type exists for: the summary can leave the machine.
// No value, no redacted form, no path, no file name, and no fingerprint —
// a CPF's fingerprint is a hash of eleven digits, which enumeration reverses.
func TestStats_CarriesNothingIdentifying(t *testing.T) {
	sessions := sampleSessions()
	out, err := json.Marshal(transcript.Summarize(sessions, 10))
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	text := string(out)

	for _, s := range sessions {
		for _, f := range s.Findings {
			for name, leak := range map[string]string{
				"value": f.Raw, "redacted value": f.Redacted,
				"fingerprint": f.Fingerprint, "location path": f.Locations[0].Path,
			} {
				if strings.Contains(text, leak) {
					t.Errorf("the summary contains the %s %q:\n%s", name, leak, text)
				}
			}
		}
		if strings.Contains(text, s.Path) || strings.Contains(text, "acme") || strings.Contains(text, "/home/") {
			t.Errorf("the summary contains a path:\n%s", text)
		}
	}
}

func TestSummarize_Empty(t *testing.T) {
	st := transcript.Summarize(nil, 0)
	if st.WithFinding != 0 || len(st.ByType) != 0 {
		t.Errorf("empty summary = %+v", st)
	}
	// An empty map, not null, so a script aggregating many machines does not
	// have to special-case a clean one.
	out, _ := json.Marshal(st)
	if !strings.Contains(string(out), `"by_type":{}`) {
		t.Errorf("by_type is not an empty object: %s", out)
	}
}
