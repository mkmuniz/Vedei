package transcript

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mkmuniz/vedei/engine"
)

const cpf = "529.982.247-25"

// writeTranscript builds a synthetic .jsonl in the shape a real agent writes.
func writeTranscript(t *testing.T, dir, name string, records []map[string]any) string {
	t.Helper()
	path := filepath.Join(dir, name)
	f, err := os.Create(path) //nolint:gosec // test temp dir
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	defer func() { _ = f.Close() }()

	enc := json.NewEncoder(f)
	for _, r := range records {
		if err := enc.Encode(r); err != nil {
			t.Fatalf("encode: %v", err)
		}
	}
	return path
}

func TestScanFile_FindsWhatAlreadyLeaked(t *testing.T) {
	dir := t.TempDir()
	path := writeTranscript(t, dir, "s.jsonl", []map[string]any{
		{"type": "user", "message": map[string]any{"content": "olha meu cpf " + cpf}},
		{"type": "assistant", "message": map[string]any{"content": "nada sensivel aqui"}},
	})

	sess, err := NewScanner(engine.Offline()).ScanFile(context.Background(), AgentClaudeCode, path)
	if err != nil {
		t.Fatalf("ScanFile: %v", err)
	}
	if len(sess.Findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(sess.Findings))
	}
	if sess.Lines != 2 {
		t.Errorf("Lines = %d, want 2", sess.Lines)
	}
	if sess.Findings[0].Locations[0].Line != 1 {
		t.Errorf("finding should be on line 1, got %d", sess.Findings[0].Locations[0].Line)
	}
}

// The value sits at a different depth in every agent and every version.
// Walking the decoded record rather than modelling a schema is what keeps a
// field rename from silently hiding a leak.
func TestScanFile_FindsValueAtAnyDepth(t *testing.T) {
	dir := t.TempDir()
	path := writeTranscript(t, dir, "deep.jsonl", []map[string]any{
		{"type": "assistant", "message": map[string]any{
			"content": []any{
				map[string]any{"type": "tool_result", "content": []any{
					map[string]any{"text": "saida do terminal: " + cpf},
				}},
			},
		}},
	})

	sess, err := NewScanner(engine.Offline()).ScanFile(context.Background(), AgentClaudeCode, path)
	if err != nil {
		t.Fatalf("ScanFile: %v", err)
	}
	if len(sess.Findings) != 1 {
		t.Fatalf("a value nested four levels deep was missed: %+v", sess.Findings)
	}
}

// Auditing must not itself become a leak.
func TestScanFile_ReportNeverContainsTheValue(t *testing.T) {
	dir := t.TempDir()
	path := writeTranscript(t, dir, "s.jsonl", []map[string]any{
		{"type": "user", "message": map[string]any{"content": "cpf " + cpf}},
	})

	sess, _ := NewScanner(engine.Offline()).ScanFile(context.Background(), AgentClaudeCode, path)
	b, err := json.Marshal(sess)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(b), cpf) || strings.Contains(string(b), "52998224725") {
		t.Fatalf("the audit report leaked the value: %s", b)
	}
}

func TestScanFile_SameValueTwiceIsOneFinding(t *testing.T) {
	dir := t.TempDir()
	path := writeTranscript(t, dir, "s.jsonl", []map[string]any{
		{"type": "user", "message": "cpf " + cpf},
		{"type": "user", "message": "de novo " + cpf},
	})

	sess, _ := NewScanner(engine.Offline()).ScanFile(context.Background(), AgentClaudeCode, path)
	if len(sess.Findings) != 1 {
		t.Fatalf("want 1 deduplicated finding, got %d", len(sess.Findings))
	}
	if len(sess.Findings[0].Locations) != 2 {
		t.Errorf("want 2 locations, got %d", len(sess.Findings[0].Locations))
	}
}

// A corrupt line must not stop the audit: the rest of the file may hold the
// leak that matters.
func TestScanFile_MalformedLineDoesNotStopTheScan(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "broken.jsonl")
	content := "{not json at all\n" +
		`{"type":"user","message":"cpf ` + cpf + `"}` + "\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	sess, err := NewScanner(engine.Offline()).ScanFile(context.Background(), AgentClaudeCode, path)
	if err != nil {
		t.Fatalf("ScanFile: %v", err)
	}
	if len(sess.Findings) != 1 {
		t.Errorf("a malformed line hid the finding after it: %+v", sess.Findings)
	}
}

func TestScanDir_WalksAndSortsByRecency(t *testing.T) {
	dir := t.TempDir()
	writeTranscript(t, dir, "a.jsonl", []map[string]any{{"m": "cpf " + cpf}})
	writeTranscript(t, dir, "b.jsonl", []map[string]any{{"m": "nada aqui"}})
	if err := os.WriteFile(filepath.Join(dir, "ignore.txt"), []byte(cpf), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	rep, err := NewScanner(engine.Offline()).ScanDir(context.Background(), AgentClaudeCode, dir)
	if err != nil {
		t.Fatalf("ScanDir: %v", err)
	}
	if rep.Scanned != 2 {
		t.Errorf("Scanned = %d, want 2 (the .txt must be ignored)", rep.Scanned)
	}
	// Only the session with findings is reported.
	if len(rep.Sessions) != 1 {
		t.Errorf("want 1 session with findings, got %d", len(rep.Sessions))
	}
	if rep.TotalFindings() != 1 {
		t.Errorf("TotalFindings = %d", rep.TotalFindings())
	}
}

func TestScanDir_EmptyDirectory(t *testing.T) {
	rep, err := NewScanner(engine.Offline()).ScanDir(context.Background(), AgentClaudeCode, t.TempDir())
	if err != nil {
		t.Fatalf("ScanDir: %v", err)
	}
	if rep.Scanned != 0 || len(rep.Sessions) != 0 {
		t.Errorf("unexpected result for an empty directory: %+v", rep)
	}
}

func TestReadableText_DepthIsBounded(t *testing.T) {
	// A record nested past the limit must return rather than exhaust the stack.
	deep := any("bottom")
	for i := 0; i < 200; i++ {
		deep = map[string]any{"n": deep}
	}
	b, err := json.Marshal(deep)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	_ = readableText(b) // must not panic
}
