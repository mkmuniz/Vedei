package main

import (
	"strings"
	"testing"
)

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
