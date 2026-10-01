// Package corpus loads the labeled examples that measure detection quality.
//
// It is the measurement tool the milestones call for: a scanner's worth is not
// "does it compile" but "what does it catch and what does it cry wolf over",
// and in Portuguese the second question is the hard one. The upstream secret
// rules score candidates against an English dictionary, so a Portuguese word
// like "senhapadrao" reads as random and is reported. That cost is only visible
// against labeled data, which is what this package is.
//
// A case file is plain text, one directive per line:
//
//	expect cpf   529.982.247-25     # a true positive: must be found, as a cpf
//	reject       529.982.247-00     # a false positive: must not be reported
//	reject       commit 20240915... # a timestamp, not a document
//
// Everything after '#' is a comment, and a comment is not decoration: a reject
// case without a reason is a line nobody can re-judge later.
package corpus

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Kind is what a case asserts about its text.
type Kind int

const (
	// Expect means the text must be reported, with the named type. It measures
	// recall: a miss here is a leak the scanner walked past.
	Expect Kind = iota
	// Reject means the text must not be reported at all. It measures precision:
	// a hit here is the scanner crying wolf, which on the agent hook means
	// redacting something the model needed.
	Reject
)

// Case is one labeled example.
type Case struct {
	Kind Kind
	// Type is the finding type an Expect case requires, such as "cpf" or
	// "aws-access-key-id". Empty for a Reject case.
	Type string
	// Text is the line fed to the engine.
	Text string
	// Reason is the comment that followed the directive. Required on a Reject,
	// because a false-positive fixture nobody can explain is one nobody can
	// safely remove.
	Reason string
	// Source locates the case for an error message.
	Source string
	Line   int
}

// Parse reads cases from one file's contents.
//
// A malformed line is an error, not a skip. A corpus that silently drops a case
// it could not parse is a corpus that reports a precision it did not measure.
func Parse(source string, r io.Reader) ([]Case, error) {
	var cases []Case
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 4<<10), 1<<20)

	for line := 1; sc.Scan(); line++ {
		raw := sc.Text()

		text, reason := splitComment(raw)
		text = strings.TrimSpace(text)
		if text == "" {
			// A blank line, or a line that was only a comment. Either is fine.
			continue
		}

		c, err := parseDirective(text, reason)
		if err != nil {
			return nil, fmt.Errorf("%s:%d: %w", source, line, err)
		}
		c.Source, c.Line = source, line
		cases = append(cases, c)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("reading %s: %w", source, err)
	}
	return cases, nil
}

// parseDirective reads one non-comment line into a Case.
func parseDirective(text, reason string) (Case, error) {
	fields := strings.Fields(text)
	switch fields[0] {
	case "expect":
		// expect <type> <text...>
		if len(fields) < 3 {
			return Case{}, fmt.Errorf("expect needs a type and a value: %q", text)
		}
		rest := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(text), "expect"))
		typ := fields[1]
		value := strings.TrimSpace(strings.TrimPrefix(rest, typ))
		if value == "" {
			return Case{}, fmt.Errorf("expect %s has no value", typ)
		}
		return Case{Kind: Expect, Type: typ, Text: value}, nil

	case "reject":
		// reject <text...>
		value := strings.TrimSpace(strings.TrimPrefix(text, "reject"))
		if value == "" {
			return Case{}, fmt.Errorf("reject has no value")
		}
		if strings.TrimSpace(reason) == "" {
			return Case{}, fmt.Errorf("reject %q has no reason; add one after '#'", value)
		}
		return Case{Kind: Reject, Text: value, Reason: strings.TrimSpace(reason)}, nil

	default:
		return Case{}, fmt.Errorf("unknown directive %q, want expect or reject", fields[0])
	}
}

// splitComment separates a line from its trailing comment. A '#' inside the
// value would be unusual for these document types, so the first one wins.
func splitComment(line string) (text, comment string) {
	if i := strings.IndexByte(line, '#'); i >= 0 {
		return line[:i], line[i+1:]
	}
	return line, ""
}

// Load reads every .txt file under dir, in a stable order so a failure names
// the same case across runs.
func Load(dir string) ([]Case, error) {
	entries, err := filepath.Glob(filepath.Join(dir, "*.txt"))
	if err != nil {
		return nil, fmt.Errorf("corpus: listing %s: %w", dir, err)
	}
	sort.Strings(entries)

	var all []Case
	for _, path := range entries {
		f, err := os.Open(path) //#nosec G304 -- a corpus fixture path from this repo's own tree
		if err != nil {
			return nil, fmt.Errorf("corpus: %w", err)
		}
		cases, err := Parse(filepath.Base(path), f)
		_ = f.Close()
		if err != nil {
			return nil, err
		}
		all = append(all, cases...)
	}
	return all, nil
}

// Metrics is the precision and recall a run measured.
type Metrics struct {
	// TruePositives is Expect cases reported with the right type.
	TruePositives int
	// FalseNegatives is Expect cases the scanner missed.
	FalseNegatives int
	// FalsePositives is Reject cases the scanner reported anyway.
	FalsePositives int
	// TrueNegatives is Reject cases the scanner correctly left alone.
	TrueNegatives int
}

// Precision is of what was reported, how much should have been. The number this
// corpus exists to defend.
func (m Metrics) Precision() float64 {
	reported := m.TruePositives + m.FalsePositives
	if reported == 0 {
		return 1
	}
	return float64(m.TruePositives) / float64(reported)
}

// Recall is of what should have been reported, how much was. The counterweight:
// precision is trivial to maximize by reporting nothing, and recall is what
// stops that.
func (m Metrics) Recall() float64 {
	actual := m.TruePositives + m.FalseNegatives
	if actual == 0 {
		return 1
	}
	return float64(m.TruePositives) / float64(actual)
}

// String renders the metrics for a test log.
func (m Metrics) String() string {
	return fmt.Sprintf("precision %.3f (%d reported, %d wrong), recall %.3f (%d/%d found)",
		m.Precision(), m.TruePositives+m.FalsePositives, m.FalsePositives,
		m.Recall(), m.TruePositives, m.TruePositives+m.FalseNegatives)
}
