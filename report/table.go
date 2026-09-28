package report

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/mkmuniz/nadzor/detect"
)

// maxValueWidth keeps a long redacted value from stretching the table past a
// terminal. The value is already masked, so the tail is what a reader matches
// against what they expected.
const maxValueWidth = 26

func writeTable(w io.Writer, run Run) error {
	if len(run.Findings) == 0 {
		_, err := fmt.Fprintf(w, "%s: nothing found in %d file(s) (%s)\n",
			run.Target, run.Scanned, humanBytes(run.Bytes))
		if err != nil {
			return fmt.Errorf("report: writing table: %w", err)
		}
		return writeTableFooter(w, run)
	}

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "SEVERITY\tTYPE\tVALUE\tWHERE")
	for _, f := range bySeverity(run.Findings) {
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n",
			sarifLevel(f), f.Type, truncate(f.Redacted, maxValueWidth), whereOf(f))
	}
	if err := tw.Flush(); err != nil {
		return fmt.Errorf("report: writing table: %w", err)
	}

	byType := map[string]int{}
	for _, f := range run.Findings {
		byType[f.Type]++
	}
	types := make([]string, 0, len(byType))
	for t := range byType {
		types = append(types, t)
	}
	sort.Strings(types)

	parts := make([]string, 0, len(types))
	for _, t := range types {
		parts = append(parts, fmt.Sprintf("%d %s", byType[t], t))
	}

	// "in N file(s)" counts the files that held something, not the files that
	// were read. Conflating the two reads as though every file was a hit.
	places := map[string]bool{}
	for _, f := range run.Findings {
		for _, loc := range f.Locations {
			places[loc.Path] = true
		}
	}

	_, err := fmt.Fprintf(w, "\n%d finding(s) — %s — in %d file(s); %d scanned, %s, %s\n",
		len(run.Findings), strings.Join(parts, ", "), len(places), run.Scanned,
		humanBytes(run.Bytes), run.Duration.Round(time.Millisecond))
	if err != nil {
		return fmt.Errorf("report: writing table: %w", err)
	}
	return writeTableFooter(w, run)
}

// writeTableFooter reports what the run did not cover. A scan that skipped
// files or silenced findings must say so, or "nothing found" is a lie by
// omission.
func writeTableFooter(w io.Writer, run Run) error {
	if run.Ignored > 0 {
		if _, err := fmt.Fprintf(w, "%d finding(s) silenced by .nadzorignore\n", run.Ignored); err != nil {
			return fmt.Errorf("report: writing table: %w", err)
		}
	}
	if run.Skipped > 0 {
		if _, err := fmt.Fprintf(w, "%d file(s) skipped (ignored, binary, symlink or over the size cap)\n",
			run.Skipped); err != nil {
			return fmt.Errorf("report: writing table: %w", err)
		}
	}
	for _, e := range run.Errors {
		if _, err := fmt.Fprintf(w, "error: %s\n", e); err != nil {
			return fmt.Errorf("report: writing table: %w", err)
		}
	}
	return nil
}

// whereOf renders the first location plus a count of the rest, because a value
// in forty places should not print forty lines.
func whereOf(f detect.Finding) string {
	if len(f.Locations) == 0 {
		return "—"
	}
	first := f.Locations[0]
	at := first.Path
	if at == "" {
		at = "(stdin)"
	}
	if first.Line > 0 {
		at = fmt.Sprintf("%s:%d", at, first.Line)
	}
	if n := len(f.Locations) - 1; n > 0 {
		at = fmt.Sprintf("%s (+%d more)", at, n)
	}
	return at
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return "..." + s[len(s)-n+3:]
}

func humanBytes(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%d B", n)
	}
}
