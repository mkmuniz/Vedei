package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"time"

	"github.com/mkmuniz/vedei/detect"
)

// Format is an output format.
type Format string

// The formats a caller can ask for.
const (
	// FormatTable is the human-readable default.
	FormatTable Format = "table"
	// FormatJSON is one object holding the whole run.
	FormatJSON Format = "json"
	// FormatJSONL is one finding per line, for streaming into something else.
	FormatJSONL Format = "jsonl"
	// FormatSARIF is what GitHub Code Scanning consumes.
	FormatSARIF Format = "sarif"
)

// Formats is every valid value, for flag help and validation.
var Formats = []Format{FormatTable, FormatJSON, FormatJSONL, FormatSARIF}

// ParseFormat validates a format name.
func ParseFormat(s string) (Format, error) {
	for _, f := range Formats {
		if Format(s) == f {
			return f, nil
		}
	}
	return "", fmt.Errorf("unknown format %q, want one of %v", s, Formats)
}

// Run is everything one scan produced, and the input to every format.
type Run struct {
	Tool     string           `json:"tool"`
	Version  string           `json:"version"`
	Target   string           `json:"target"`
	Started  time.Time        `json:"started"`
	Duration time.Duration    `json:"duration_ns"`
	Scanned  int              `json:"scanned"`
	Skipped  int              `json:"skipped,omitempty"`
	Ignored  int              `json:"ignored,omitempty"`
	Bytes    int64            `json:"bytes"`
	Findings []detect.Finding `json:"findings"`
	Errors   []string         `json:"errors,omitempty"`
}

// Write emits the run in the requested format.
//
// Every format goes through detect.Finding's own JSON tags, so none of them can
// emit Finding.Raw: the field is json:"-" and there is no second path.
func Write(w io.Writer, f Format, run Run) error {
	switch f {
	case FormatJSON:
		return writeJSON(w, run)
	case FormatJSONL:
		return writeJSONL(w, run)
	case FormatSARIF:
		return WriteSARIF(w, run)
	case FormatTable:
		return writeTable(w, run)
	default:
		return fmt.Errorf("report: unknown format %q", f)
	}
}

func writeJSON(w io.Writer, run Run) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if run.Findings == nil {
		// An empty array, never null: a consumer that does `.findings | length`
		// should not have to special-case a clean run.
		run.Findings = []detect.Finding{}
	}
	if err := enc.Encode(run); err != nil {
		return fmt.Errorf("report: writing JSON: %w", err)
	}
	return nil
}

func writeJSONL(w io.Writer, run Run) error {
	enc := json.NewEncoder(w)
	for _, f := range run.Findings {
		if err := enc.Encode(f); err != nil {
			return fmt.Errorf("report: writing JSONL: %w", err)
		}
	}
	return nil
}

// bySeverity orders findings for display: the ones a person should look at
// first, then stably by type and fingerprint so two runs of the same tree
// produce identical output.
func bySeverity(findings []detect.Finding) []detect.Finding {
	out := make([]detect.Finding, len(findings))
	copy(out, findings)

	rank := map[detect.Confidence]int{
		detect.ConfidenceHigh:   0,
		detect.ConfidenceMedium: 1,
		detect.ConfidenceLow:    2,
	}
	sort.SliceStable(out, func(i, j int) bool {
		if a, b := rank[out[i].Confidence], rank[out[j].Confidence]; a != b {
			return a < b
		}
		if out[i].Type != out[j].Type {
			return out[i].Type < out[j].Type
		}
		return out[i].Fingerprint < out[j].Fingerprint
	})
	return out
}
