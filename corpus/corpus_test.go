package corpus_test

import (
	"context"
	"strings"
	"testing"

	"github.com/mkmuniz/vedei/corpus"
	"github.com/mkmuniz/vedei/detect"
	"github.com/mkmuniz/vedei/engine"
)

// casesDir is the labeled data, relative to this test.
const casesDir = "cases"

// TestCorpus runs every labeled case through the full engine and fails on any
// violation, reporting precision and recall as it goes.
//
// The gate is strict — every Expect must be found, every Reject must stay quiet
// — rather than a threshold, because this corpus is hand-labeled. A threshold is
// for a noisy, scraped corpus where some error is expected; here every case is a
// claim someone wrote down on purpose, so any miss is a regression. The metrics
// are still printed, because the numbers are the point of the exercise and a
// reviewer should see them move.
func TestCorpus(t *testing.T) {
	cases, err := corpus.Load(casesDir)
	if err != nil {
		t.Fatalf("loading the corpus: %v", err)
	}
	if len(cases) == 0 {
		t.Fatal("the corpus is empty")
	}

	eng := engine.All()
	report := corpus.NewReport()

	for _, c := range cases {
		types := typesFound(t, eng, c.Text)
		if report.Record(c, types) {
			continue
		}
		switch c.Kind {
		case corpus.Expect:
			t.Errorf("%s:%d: expected %s in %q, found %v",
				c.Source, c.Line, c.Type, c.Text, keys(types))
		case corpus.Reject:
			t.Errorf("%s:%d: %q should be quiet (%s), but was reported as %v",
				c.Source, c.Line, c.Text, c.Reason, keys(types))
		}
	}

	// The strict gate above is the explicit target: precision and recall of
	// 1.000 for every type, which is stricter than the 0.99 floor the project
	// sets for types with a check digit. The table shows where each type stands,
	// so a type drifting toward that floor is visible before it crosses it.
	t.Logf("%d cases: %s\n%s", len(cases), report.Overall, report.Table())
}

// typesFound returns the set of finding types the engine reports for text.
func typesFound(t *testing.T, eng detect.Engine, text string) map[string]bool {
	t.Helper()
	findings, err := eng.Scan(context.Background(), []byte(text), detect.Metadata{Source: "corpus"})
	if err != nil {
		t.Fatalf("scanning %q: %v", text, err)
	}
	types := make(map[string]bool, len(findings))
	for _, f := range findings {
		types[f.Type] = true
	}
	return types
}

func keys(m map[string]bool) []string {
	if len(m) == 0 {
		return []string{"nothing"}
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// TestCorpus_MetricsMath guards the two formulas, since a corpus that miscounts
// its own precision is worse than none.
func TestCorpus_MetricsMath(t *testing.T) {
	m := corpus.Metrics{TruePositives: 8, FalsePositives: 2, FalseNegatives: 1, TrueNegatives: 5}
	if got := m.Precision(); got != 0.8 {
		t.Errorf("Precision() = %v, want 0.8", got)
	}
	if got := m.Recall(); !approx(got, 8.0/9.0) {
		t.Errorf("Recall() = %v, want 0.889", got)
	}

	// An empty count is defined as perfect, so a run with no cases of a kind
	// does not read as a failure.
	empty := corpus.Metrics{}
	if empty.Precision() != 1 || empty.Recall() != 1 {
		t.Errorf("empty metrics = %v", empty)
	}
}

// A false positive is charged to the type that was wrongly reported, and a miss
// to the type that was expected. That attribution is what makes the per-type
// table mean something; get it wrong and a noisy type hides behind a clean one.
func TestReport_Record(t *testing.T) {
	tests := []struct {
		name     string
		c        corpus.Case
		found    map[string]bool
		wantPass bool
		check    func(t *testing.T, r *corpus.Report)
	}{
		{
			name:     "expect found",
			c:        corpus.Case{Kind: corpus.Expect, Type: "cpf"},
			found:    map[string]bool{"cpf": true},
			wantPass: true,
			check: func(t *testing.T, r *corpus.Report) {
				if got := r.Type("cpf").TruePositives; got != 1 {
					t.Errorf("cpf TruePositives = %d, want 1", got)
				}
			},
		},
		{
			name:     "expect found under the wrong type is a miss",
			c:        corpus.Case{Kind: corpus.Expect, Type: "cpf"},
			found:    map[string]bool{"cnh": true},
			wantPass: false,
			check: func(t *testing.T, r *corpus.Report) {
				if got := r.Type("cpf").FalseNegatives; got != 1 {
					t.Errorf("cpf FalseNegatives = %d, want 1", got)
				}
			},
		},
		{
			name:     "reject reported is charged to the reported type",
			c:        corpus.Case{Kind: corpus.Reject},
			found:    map[string]bool{"card-pan": true},
			wantPass: false,
			check: func(t *testing.T, r *corpus.Report) {
				if got := r.Type("card-pan").FalsePositives; got != 1 {
					t.Errorf("card-pan FalsePositives = %d, want 1", got)
				}
				if got := r.Overall.FalsePositives; got != 1 {
					t.Errorf("overall FalsePositives = %d, want 1", got)
				}
			},
		},
		{
			name:     "reject left alone belongs to no type",
			c:        corpus.Case{Kind: corpus.Reject},
			found:    map[string]bool{},
			wantPass: true,
			check: func(t *testing.T, r *corpus.Report) {
				if len(r.Types()) != 0 {
					t.Errorf("types = %v, want none", r.Types())
				}
				if r.Overall.TrueNegatives != 1 {
					t.Errorf("overall TrueNegatives = %d, want 1", r.Overall.TrueNegatives)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := corpus.NewReport()
			if got := r.Record(tt.c, tt.found); got != tt.wantPass {
				t.Errorf("Record() = %v, want %v", got, tt.wantPass)
			}
			tt.check(t, r)
		})
	}
}

func approx(a, b float64) bool {
	d := a - b
	return d < 1e-9 && d > -1e-9
}

func TestParse_RejectsMalformed(t *testing.T) {
	for _, bad := range []string{
		"expect",       // no type, no value
		"expect cpf",   // no value
		"reject",       // no value
		"reject 123",   // no reason
		"wat 123  # x", // unknown directive
	} {
		if _, err := corpus.Parse("t", strings.NewReader(bad)); err == nil {
			t.Errorf("Parse(%q) accepted a malformed line", bad)
		}
	}
}

func TestParse_ReadsBothDirectives(t *testing.T) {
	in := `
# a comment
expect cpf  529.982.247-25
reject  000.000.000-00   # repeated digits
`
	cases, err := corpus.Parse("t", strings.NewReader(in))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(cases) != 2 {
		t.Fatalf("got %d cases, want 2", len(cases))
	}
	if cases[0].Kind != corpus.Expect || cases[0].Type != "cpf" || cases[0].Text != "529.982.247-25" {
		t.Errorf("first case = %+v", cases[0])
	}
	if cases[1].Kind != corpus.Reject || cases[1].Reason != "repeated digits" {
		t.Errorf("second case = %+v", cases[1])
	}
}
