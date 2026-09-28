package transcript_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mkmuniz/nadzor/engine"
	"github.com/mkmuniz/nadzor/transcript"
)

const scrubCPF = "529.982.247-25"

// writeTranscript writes a .jsonl file and returns its path.
func writeTranscript(t *testing.T, lines ...string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "session.jsonl")
	body := strings.Join(lines, "\n") + "\n"
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return p
}

func scrubber(t *testing.T) *transcript.Scanner {
	t.Helper()
	return transcript.NewScanner(engine.Offline())
}

func read(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p) //nolint:gosec // a path this test wrote
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	return string(b)
}

func TestScrub_RemovesTheValueAndKeepsValidJSON(t *testing.T) {
	p := writeTranscript(t,
		`{"type":"user","message":{"content":"meu cpf e `+scrubCPF+` ok"}}`,
		`{"type":"assistant","message":{"content":"entendi"}}`,
	)

	res, err := scrubber(t).Scrub(context.Background(), transcript.AgentClaudeCode, p,
		transcript.ScrubOptions{Annotate: true})
	if err != nil {
		t.Fatalf("Scrub: %v", err)
	}

	out := read(t, p)
	if strings.Contains(out, scrubCPF) {
		t.Fatalf("the value survived:\n%s", out)
	}
	if !strings.Contains(out, "nadzor: cpf redacted") {
		t.Errorf("no annotation:\n%s", out)
	}

	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 2 {
		t.Fatalf("want 2 records, got %d", len(lines))
	}
	for i, l := range lines {
		if !json.Valid([]byte(l)) {
			t.Errorf("record %d is not valid JSON: %s", i+1, l)
		}
	}
	if res.LinesChanged != 1 || res.Replacements != 1 {
		t.Errorf("LinesChanged = %d, Replacements = %d, want 1 and 1", res.LinesChanged, res.Replacements)
	}
}

// The criterion this command exists to satisfy: the backup is byte-for-byte.
func TestScrub_BackupIsIdenticalToTheOriginal(t *testing.T) {
	original := `{"content":"cpf ` + scrubCPF + `"}`
	p := writeTranscript(t, original)
	before := read(t, p)

	res, err := scrubber(t).Scrub(context.Background(), transcript.AgentClaudeCode, p, transcript.ScrubOptions{})
	if err != nil {
		t.Fatalf("Scrub: %v", err)
	}
	if res.Backup == "" {
		t.Fatal("no backup was made")
	}
	if got := read(t, res.Backup); got != before {
		t.Errorf("the backup differs from the original:\n got %q\nwant %q", got, before)
	}
	if read(t, p) == before {
		t.Error("the transcript was not changed")
	}
}

// A dry run must be exactly that.
func TestScrub_DryRunWritesNothing(t *testing.T) {
	p := writeTranscript(t, `{"content":"cpf `+scrubCPF+`"}`)
	before := read(t, p)

	res, err := scrubber(t).Scrub(context.Background(), transcript.AgentClaudeCode, p,
		transcript.ScrubOptions{DryRun: true})
	if err != nil {
		t.Fatalf("Scrub: %v", err)
	}

	if got := read(t, p); got != before {
		t.Error("a dry run modified the file")
	}
	if res.Backup != "" {
		t.Errorf("a dry run made a backup at %s", res.Backup)
	}
	// It still has to report what it would do, or there is no point running it.
	if res.Replacements != 1 || res.LinesChanged != 1 {
		t.Errorf("Replacements = %d, LinesChanged = %d, want 1 and 1", res.Replacements, res.LinesChanged)
	}
	if len(res.Findings) != 1 {
		t.Errorf("want 1 finding, got %d", len(res.Findings))
	}

	// No temporary file was left beside it either.
	entries, err := os.ReadDir(filepath.Dir(p))
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 1 {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("the directory holds %v, want only the transcript", names)
	}
}

// A clean transcript is not touched at all: no rewrite, no backup, no new mtime.
func TestScrub_CleanTranscriptIsUntouched(t *testing.T) {
	p := writeTranscript(t, `{"content":"nada sensivel"}`)
	before, err := os.Stat(p)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}

	res, err := scrubber(t).Scrub(context.Background(), transcript.AgentClaudeCode, p, transcript.ScrubOptions{})
	if err != nil {
		t.Fatalf("Scrub: %v", err)
	}
	if res.Backup != "" || res.LinesChanged != 0 {
		t.Errorf("a clean transcript produced %+v", res)
	}

	after, err := os.Stat(p)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if !after.ModTime().Equal(before.ModTime()) {
		t.Error("a clean transcript was rewritten")
	}
}

// A plain decode turns every number into a float64, which rewrites a
// millisecond timestamp into scientific notation. Walking tokens keeps it.
func TestScrub_PreservesNumbersExactly(t *testing.T) {
	p := writeTranscript(t,
		`{"ts":1759000000123,"cost":0.00012345,"big":123456789012345678,"content":"cpf `+scrubCPF+`"}`)

	if _, err := scrubber(t).Scrub(context.Background(), transcript.AgentClaudeCode, p,
		transcript.ScrubOptions{}); err != nil {
		t.Fatalf("Scrub: %v", err)
	}

	out := read(t, p)
	for _, want := range []string{"1759000000123", "0.00012345", "123456789012345678"} {
		if !strings.Contains(out, want) {
			t.Errorf("the number %s did not survive:\n%s", want, out)
		}
	}
}

// Key order is part of how a transcript reads, and a map loses it.
func TestScrub_PreservesKeyOrder(t *testing.T) {
	p := writeTranscript(t, `{"zebra":1,"alpha":2,"content":"cpf `+scrubCPF+`","middle":3}`)

	if _, err := scrubber(t).Scrub(context.Background(), transcript.AgentClaudeCode, p,
		transcript.ScrubOptions{}); err != nil {
		t.Fatalf("Scrub: %v", err)
	}

	out := strings.TrimSpace(read(t, p))
	wantOrder := []string{`"zebra"`, `"alpha"`, `"content"`, `"middle"`}
	at := 0
	for _, key := range wantOrder {
		i := strings.Index(out[at:], key)
		if i < 0 {
			t.Fatalf("key %s is missing or out of order:\n%s", key, out)
		}
		at += i
	}
}

// Nested structures are where a rewrite most easily loses something.
func TestScrub_ReachesNestedValues(t *testing.T) {
	p := writeTranscript(t,
		`{"a":{"b":[{"c":"cpf `+scrubCPF+`"},{"d":[["cpf `+scrubCPF+`"]]}]},"n":null,"t":true}`)

	res, err := scrubber(t).Scrub(context.Background(), transcript.AgentClaudeCode, p,
		transcript.ScrubOptions{})
	if err != nil {
		t.Fatalf("Scrub: %v", err)
	}

	out := read(t, p)
	if strings.Contains(out, scrubCPF) {
		t.Errorf("a nested value survived:\n%s", out)
	}
	if res.Replacements != 2 {
		t.Errorf("Replacements = %d, want 2", res.Replacements)
	}
	if !json.Valid([]byte(strings.TrimSpace(out))) {
		t.Errorf("the rewrite is not valid JSON:\n%s", out)
	}
	for _, want := range []string{`"n":null`, `"t":true`} {
		if !strings.Contains(out, want) {
			t.Errorf("%s did not survive:\n%s", want, out)
		}
	}
}

// A transcript that already held a malformed line keeps it, malformed, rather
// than having the record dropped.
func TestScrub_HandlesANonJSONRecord(t *testing.T) {
	p := writeTranscript(t,
		`not json at all, cpf `+scrubCPF,
		`{"content":"cpf `+scrubCPF+`"}`,
	)

	if _, err := scrubber(t).Scrub(context.Background(), transcript.AgentClaudeCode, p,
		transcript.ScrubOptions{}); err != nil {
		t.Fatalf("Scrub: %v", err)
	}

	out := read(t, p)
	if strings.Contains(out, scrubCPF) {
		t.Errorf("the value survived in the malformed record:\n%s", out)
	}
	if lines := strings.Split(strings.TrimSpace(out), "\n"); len(lines) != 2 {
		t.Errorf("want 2 records, got %d:\n%s", len(lines), out)
	}
}

// Escaped content is where a naive byte-level replacement breaks the JSON.
func TestScrub_PreservesEscapesAndUnicode(t *testing.T) {
	p := writeTranscript(t,
		`{"content":"linha1\nlinha2\t\"citado\" <tag> ação 日本 cpf `+scrubCPF+`"}`)

	if _, err := scrubber(t).Scrub(context.Background(), transcript.AgentClaudeCode, p,
		transcript.ScrubOptions{}); err != nil {
		t.Fatalf("Scrub: %v", err)
	}

	out := strings.TrimSpace(read(t, p))
	if !json.Valid([]byte(out)) {
		t.Fatalf("the rewrite is not valid JSON:\n%s", out)
	}

	var rec struct{ Content string }
	if err := json.Unmarshal([]byte(out), &rec); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, want := range []string{"linha1\nlinha2\t", `"citado"`, "<tag>", "ação", "日本"} {
		if !strings.Contains(rec.Content, want) {
			t.Errorf("%q did not survive: %q", want, rec.Content)
		}
	}
	// "<" must not come back as \u003c, which would change bytes nobody asked
	// about.
	if strings.Contains(out, `\u003c`) {
		t.Errorf("HTML escaping was applied:\n%s", out)
	}
}

func TestScrub_NoBackup(t *testing.T) {
	p := writeTranscript(t, `{"content":"cpf `+scrubCPF+`"}`)

	res, err := scrubber(t).Scrub(context.Background(), transcript.AgentClaudeCode, p,
		transcript.ScrubOptions{NoBackup: true})
	if err != nil {
		t.Fatalf("Scrub: %v", err)
	}
	if res.Backup != "" {
		t.Errorf("a backup was made at %s despite NoBackup", res.Backup)
	}
	if strings.Contains(read(t, p), scrubCPF) {
		t.Error("the value survived")
	}
}

// The mode is preserved, because a transcript that becomes world-readable after
// a scrub is a worse outcome than the leak it removed.
func TestScrub_PreservesFileMode(t *testing.T) {
	p := writeTranscript(t, `{"content":"cpf `+scrubCPF+`"}`)
	if err := os.Chmod(p, 0o600); err != nil {
		t.Fatalf("Chmod: %v", err)
	}

	if _, err := scrubber(t).Scrub(context.Background(), transcript.AgentClaudeCode, p,
		transcript.ScrubOptions{}); err != nil {
		t.Fatalf("Scrub: %v", err)
	}

	info, err := os.Stat(p)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("mode = %o, want 600", perm)
	}
}

// After a scrub, a rescan has to come back clean. Anything else means the
// rewrite missed a form of the value it claimed to remove.
func TestScrub_RescanIsClean(t *testing.T) {
	p := writeTranscript(t,
		`{"content":"cpf `+scrubCPF+` e sem mascara 52998224725"}`,
		`{"content":"cnpj 11.222.333/0001-81"}`,
	)

	sc := scrubber(t)
	if _, err := sc.Scrub(context.Background(), transcript.AgentClaudeCode, p,
		transcript.ScrubOptions{}); err != nil {
		t.Fatalf("Scrub: %v", err)
	}

	after, err := sc.ScanFile(context.Background(), transcript.AgentClaudeCode, p)
	if err != nil {
		t.Fatalf("ScanFile: %v", err)
	}
	if len(after.Findings) != 0 {
		types := make([]string, 0, len(after.Findings))
		for _, f := range after.Findings {
			types = append(types, f.Type+"="+f.Redacted)
		}
		t.Errorf("a rescan still finds %v:\n%s", types, read(t, p))
	}
}

func TestScrub_MissingFileIsAnError(t *testing.T) {
	_, err := scrubber(t).Scrub(context.Background(), transcript.AgentClaudeCode,
		filepath.Join(t.TempDir(), "nope.jsonl"), transcript.ScrubOptions{})
	if err == nil {
		t.Fatal("scrubbing a missing file returned no error")
	}
}

// The bug that made the scrub rewrite: findings are deduplicated by a
// fingerprint that normalizes punctuation, so one finding holds one spelling.
// Substituting that spelling left the other one in the file, and a rescan came
// back dirty. Scanning each string and replacing by offset has no such gap.
func TestScrub_CatchesEverySpellingOfTheSameValue(t *testing.T) {
	// Both spellings the CPF extractor accepts. Space-separated — "529 982 247
	// 25" — is not one of them; see the note in ARCHITECTURE.md.
	p := writeTranscript(t,
		`{"a":"cpf `+scrubCPF+`","b":"o mesmo sem mascara 52998224725"}`)

	res, err := scrubber(t).Scrub(context.Background(), transcript.AgentClaudeCode, p,
		transcript.ScrubOptions{})
	if err != nil {
		t.Fatalf("Scrub: %v", err)
	}

	out := read(t, p)
	for _, spelling := range []string{scrubCPF, "52998224725"} {
		if strings.Contains(out, spelling) {
			t.Errorf("the spelling %q survived:\n%s", spelling, out)
		}
	}
	if res.Replacements < 2 {
		t.Errorf("Replacements = %d, want at least 2 — one per spelling", res.Replacements)
	}
	// Both are one value, so the report shows one finding in two places.
	if len(res.Findings) != 1 {
		t.Errorf("want 1 deduplicated finding, got %d", len(res.Findings))
	}
}

// A scrub must not invent findings where the source had none, which is what a
// naive replacement across record boundaries would do.
func TestScrub_LeavesUnrelatedRecordsByteIdentical(t *testing.T) {
	clean := `{"type":"assistant","message":{"content":"tudo certo"},"ts":1759000000123}`
	p := writeTranscript(t, clean, `{"content":"cpf `+scrubCPF+`"}`)

	if _, err := scrubber(t).Scrub(context.Background(), transcript.AgentClaudeCode, p,
		transcript.ScrubOptions{}); err != nil {
		t.Fatalf("Scrub: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(read(t, p)), "\n")
	if lines[0] != clean {
		t.Errorf("a clean record was rewritten:\n got %s\nwant %s", lines[0], clean)
	}
}

// Findings carry the line they were on, or the report cannot point anywhere.
func TestScrub_FindingsCarryLineNumbers(t *testing.T) {
	p := writeTranscript(t,
		`{"content":"nada"}`,
		`{"content":"cpf `+scrubCPF+`"}`,
		`{"content":"de novo `+scrubCPF+`"}`,
	)

	res, err := scrubber(t).Scrub(context.Background(), transcript.AgentClaudeCode, p,
		transcript.ScrubOptions{DryRun: true})
	if err != nil {
		t.Fatalf("Scrub: %v", err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(res.Findings))
	}
	locs := res.Findings[0].Locations
	if len(locs) != 2 || locs[0].Line != 2 || locs[1].Line != 3 {
		t.Errorf("locations = %+v, want lines 2 and 3", locs)
	}
	if res.Findings[0].Extra["agent"] != string(transcript.AgentClaudeCode) {
		t.Errorf("the agent was not recorded: %v", res.Findings[0].Extra)
	}
}
