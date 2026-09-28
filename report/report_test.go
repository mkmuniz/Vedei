package report_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/mkmuniz/nadzor/detect"
	"github.com/mkmuniz/nadzor/report"
)

// rawCPF is the value that must never appear in any output. Findings carry it
// in Finding.Raw, which is json:"-"; these tests are what proves that holds for
// every format rather than only for the one somebody remembered.
const rawCPF = "529.982.247-25"

func sampleRun() report.Run {
	return report.Run{
		Tool:     "nadzor",
		Version:  "test",
		Target:   ".",
		Started:  time.Date(2026, 9, 28, 10, 0, 0, 0, time.UTC),
		Duration: 1500 * time.Millisecond,
		Scanned:  12,
		Skipped:  3,
		Ignored:  1,
		Bytes:    4096,
		Findings: []detect.Finding{
			{
				Type:        "cpf",
				Engine:      "br",
				Redacted:    "***.***.***-25",
				Raw:         rawCPF,
				Validity:    detect.ValidityStructural,
				Confidence:  detect.ConfidenceHigh,
				Reason:      "check digit valid",
				Fingerprint: "0123456789abcdef0123456789abcdef",
				Locations: []detect.Location{
					{Path: "src/a.txt", Line: 3, Column: 5, ByteStart: 20, ByteEnd: 34},
					{Path: "src/b.txt", Line: 9, Column: 1, ByteStart: 0, ByteEnd: 14},
				},
			},
			{
				Type:        "stripe-access-token",
				Engine:      "secrets",
				Redacted:    "**_****_*******dc",
				Raw:         "sk" + "_live_" + "notarealkey",
				Validity:    detect.ValidityUnknown,
				Confidence:  detect.ConfidenceMedium,
				Fingerprint: "fedcba9876543210fedcba9876543210",
				Locations:   []detect.Location{{Path: "cfg.go", Line: 1}},
				Extra:       map[string]string{"rule": "stripe"},
			},
		},
		Errors: []string{"scan: open locked.txt: permission denied"},
	}
}

func write(t *testing.T, f report.Format, run report.Run) string {
	t.Helper()
	var buf bytes.Buffer
	if err := report.Write(&buf, f, run); err != nil {
		t.Fatalf("Write(%s): %v", f, err)
	}
	return buf.String()
}

// The property that matters more than any format detail.
func TestWrite_NoFormatEmitsTheRawValue(t *testing.T) {
	run := sampleRun()
	for _, f := range report.Formats {
		out := write(t, f, run)
		if strings.Contains(out, rawCPF) {
			t.Errorf("format %s leaked the value:\n%s", f, out)
		}
		if strings.Contains(out, "notarealkey") {
			t.Errorf("format %s leaked the secret:\n%s", f, out)
		}
	}
}

func TestWriteJSON_Shape(t *testing.T) {
	var got map[string]any
	if err := json.Unmarshal([]byte(write(t, report.FormatJSON, sampleRun())), &got); err != nil {
		t.Fatalf("the output is not JSON: %v", err)
	}

	findings, ok := got["findings"].([]any)
	if !ok || len(findings) != 2 {
		t.Fatalf("findings = %v", got["findings"])
	}
	first, ok := findings[0].(map[string]any)
	if !ok {
		t.Fatal("a finding is not an object")
	}
	// "value" is the redacted form; there is no key holding the original.
	if first["value"] != "***.***.***-25" {
		t.Errorf("value = %v", first["value"])
	}
	if _, present := first["raw"]; present {
		t.Error("a raw key is present in the output")
	}
}

// A consumer doing `.findings | length` should not have to special-case a
// clean run, so the array is empty rather than null.
func TestWriteJSON_CleanRunHasAnEmptyArray(t *testing.T) {
	out := write(t, report.FormatJSON, report.Run{Tool: "nadzor"})
	if !strings.Contains(out, `"findings": []`) {
		t.Errorf("a clean run emitted:\n%s", out)
	}
}

func TestWriteJSONL_OneObjectPerLine(t *testing.T) {
	out := write(t, report.FormatJSONL, sampleRun())
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 2 {
		t.Fatalf("want 2 lines, got %d:\n%s", len(lines), out)
	}
	for i, l := range lines {
		var f detect.Finding
		if err := json.Unmarshal([]byte(l), &f); err != nil {
			t.Errorf("line %d is not a Finding: %v", i+1, err)
		}
		if f.Raw != "" {
			t.Errorf("line %d carries a raw value", i+1)
		}
	}
}

func TestWriteJSONL_CleanRunIsEmpty(t *testing.T) {
	if out := write(t, report.FormatJSONL, report.Run{}); out != "" {
		t.Errorf("a clean run emitted %q", out)
	}
}

func TestWriteSARIF_ValidatesAgainstTheShapeGitHubReads(t *testing.T) {
	var log map[string]any
	if err := json.Unmarshal([]byte(write(t, report.FormatSARIF, sampleRun())), &log); err != nil {
		t.Fatalf("the output is not JSON: %v", err)
	}

	if log["version"] != "2.1.0" {
		t.Errorf("version = %v", log["version"])
	}
	if log["$schema"] == nil {
		t.Error("$schema is missing")
	}

	runs, ok := log["runs"].([]any)
	if !ok || len(runs) != 1 {
		t.Fatalf("runs = %v", log["runs"])
	}
	r, ok := runs[0].(map[string]any)
	if !ok {
		t.Fatal("the run is not an object")
	}

	results, ok := r["results"].([]any)
	if !ok || len(results) != 2 {
		t.Fatalf("results = %v", r["results"])
	}

	driver, ok := r["tool"].(map[string]any)["driver"].(map[string]any)
	if !ok {
		t.Fatal("no tool.driver")
	}
	rules, ok := driver["rules"].([]any)
	if !ok || len(rules) != 2 {
		t.Fatalf("rules = %v", driver["rules"])
	}

	// ruleIndex has to point into that array, or GitHub renders the wrong rule
	// against the finding.
	for i, raw := range results {
		res, ok := raw.(map[string]any)
		if !ok {
			t.Fatalf("result %d is not an object", i)
		}
		idx, ok := res["ruleIndex"].(float64)
		if !ok {
			t.Fatalf("result %d has no ruleIndex", i)
		}
		if int(idx) < 0 || int(idx) >= len(rules) {
			t.Fatalf("result %d: ruleIndex %v is out of range", i, idx)
		}
		rule, ok := rules[int(idx)].(map[string]any)
		if !ok {
			t.Fatalf("rule %v is not an object", idx)
		}
		if rule["id"] != res["ruleId"] {
			t.Errorf("result %d: ruleIndex points at %v, ruleId is %v", i, rule["id"], res["ruleId"])
		}
	}
}

// partialFingerprints is what makes GitHub treat a finding as the same alert
// after the file moves, which is the whole reason the fingerprint excludes the
// location.
func TestWriteSARIF_CarriesTheFingerprint(t *testing.T) {
	var log sarifShape
	if err := json.Unmarshal([]byte(write(t, report.FormatSARIF, sampleRun())), &log); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	for _, res := range log.Runs[0].Results {
		if res.PartialFingerprints["nadzorFingerprint/v1"] == "" {
			t.Errorf("%s has no partial fingerprint", res.RuleID)
		}
	}
}

// A value in two files has to produce two locations, or the alert points at one
// of them and the other is never fixed.
func TestWriteSARIF_EveryLocationIsEmitted(t *testing.T) {
	var log sarifShape
	if err := json.Unmarshal([]byte(write(t, report.FormatSARIF, sampleRun())), &log); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	for _, res := range log.Runs[0].Results {
		if res.RuleID != "cpf" {
			continue
		}
		if len(res.Locations) != 2 {
			t.Fatalf("the CPF has %d locations, want 2", len(res.Locations))
		}
		got := res.Locations[0].PhysicalLocation
		if got.ArtifactLocation.URI != "src/a.txt" {
			t.Errorf("uri = %q", got.ArtifactLocation.URI)
		}
		if got.Region == nil || got.Region.StartLine != 3 {
			t.Errorf("region = %+v", got.Region)
		}
	}
}

// A scan that hit an error must not upload as a successful invocation, or
// GitHub shows a green check over a partial scan.
func TestWriteSARIF_ReportsAFailedInvocation(t *testing.T) {
	var withErr, clean sarifShape
	if err := json.Unmarshal([]byte(write(t, report.FormatSARIF, sampleRun())), &withErr); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if err := json.Unmarshal([]byte(write(t, report.FormatSARIF, report.Run{Tool: "nadzor"})), &clean); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if withErr.Runs[0].Invocations[0].ExecutionSuccessful {
		t.Error("a run with errors reported executionSuccessful")
	}
	if n := len(withErr.Runs[0].Invocations[0].ToolExecutionNotifications); n != 1 {
		t.Errorf("want 1 notification, got %d", n)
	}
	if !clean.Runs[0].Invocations[0].ExecutionSuccessful {
		t.Error("a clean run reported a failure")
	}
}

// GitHub matches the URI against the repository tree, so a "./" prefix or a
// backslash lands the alert on no file at all.
func TestWriteSARIF_NormalizesPaths(t *testing.T) {
	run := report.Run{
		Tool: "nadzor",
		Findings: []detect.Finding{{
			Type: "cpf", Engine: "br", Redacted: "***", Confidence: detect.ConfidenceHigh,
			Fingerprint: "a", Locations: []detect.Location{{Path: `./src\win\a.txt`, Line: 1}},
		}},
	}

	var log sarifShape
	if err := json.Unmarshal([]byte(write(t, report.FormatSARIF, run)), &log); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got := log.Runs[0].Results[0].Locations[0].PhysicalLocation.ArtifactLocation.URI; got != "src/win/a.txt" {
		t.Errorf("uri = %q", got)
	}
}

// Confidence drives the level, not validity: a structurally valid CPF in a
// fixture is a true positive that is not a problem.
func TestWriteSARIF_LevelFollowsConfidence(t *testing.T) {
	run := report.Run{Tool: "nadzor", Findings: []detect.Finding{
		{Type: "high", Confidence: detect.ConfidenceHigh, Fingerprint: "a", Redacted: "*"},
		{Type: "medium", Confidence: detect.ConfidenceMedium, Fingerprint: "b", Redacted: "*"},
		{Type: "low", Confidence: detect.ConfidenceLow, Fingerprint: "c", Redacted: "*"},
		{Type: "live", Confidence: detect.ConfidenceLow, Validity: detect.ValidityLive, Fingerprint: "d", Redacted: "*"},
	}}

	var log sarifShape
	if err := json.Unmarshal([]byte(write(t, report.FormatSARIF, run)), &log); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	want := map[string]string{"high": "error", "medium": "warning", "low": "note", "live": "error"}
	for _, res := range log.Runs[0].Results {
		if got := res.Level; got != want[res.RuleID] {
			t.Errorf("%s: level = %q, want %q", res.RuleID, got, want[res.RuleID])
		}
	}
}

func TestWriteTable_CleanAndDirty(t *testing.T) {
	clean := write(t, report.FormatTable, report.Run{Tool: "nadzor", Target: ".", Scanned: 5})
	if !strings.Contains(clean, "nothing found in 5 file(s)") {
		t.Errorf("clean output:\n%s", clean)
	}

	dirty := write(t, report.FormatTable, sampleRun())
	for _, want := range []string{
		"SEVERITY", "cpf", "***.***.***-25", "src/a.txt:3", "(+1 more)",
		// The file count is the files that held something, not the files read.
		"2 finding(s)", "in 3 file(s); 12 scanned",
		"1 finding(s) silenced by .nadzorignore",
		"3 file(s) skipped", "permission denied",
	} {
		if !strings.Contains(dirty, want) {
			t.Errorf("table is missing %q:\n%s", want, dirty)
		}
	}
}

// Two runs over the same tree have to produce identical bytes, or a diff of
// reports is unreadable.
func TestWrite_IsDeterministic(t *testing.T) {
	for _, f := range report.Formats {
		a, b := write(t, f, sampleRun()), write(t, f, sampleRun())
		if a != b {
			t.Errorf("format %s is not deterministic", f)
		}
	}
}

func TestParseFormat(t *testing.T) {
	for _, f := range report.Formats {
		if got, err := report.ParseFormat(string(f)); err != nil || got != f {
			t.Errorf("ParseFormat(%q) = %v, %v", f, got, err)
		}
	}
	if _, err := report.ParseFormat("yaml"); err == nil {
		t.Error("an unknown format was accepted")
	}
}

// sarifShape is the subset of SARIF these tests assert on, declared once.
type sarifShape struct {
	Runs []struct {
		Tool struct {
			Driver struct {
				Rules []struct{ ID string } `json:"rules"`
			} `json:"driver"`
		} `json:"tool"`
		Results []struct {
			RuleID              string            `json:"ruleId"`
			RuleIndex           int               `json:"ruleIndex"`
			Level               string            `json:"level"`
			PartialFingerprints map[string]string `json:"partialFingerprints"`
			Locations           []struct {
				PhysicalLocation struct {
					ArtifactLocation struct{ URI string } `json:"artifactLocation"`
					Region           *struct {
						StartLine int `json:"startLine"`
					} `json:"region"`
				} `json:"physicalLocation"`
			} `json:"locations"`
		} `json:"results"`
		Invocations []struct {
			ExecutionSuccessful        bool `json:"executionSuccessful"`
			ToolExecutionNotifications []struct {
				Level string `json:"level"`
			} `json:"toolExecutionNotifications"`
		} `json:"invocations"`
	} `json:"runs"`
}
