package main

import (
	"fmt"

	"github.com/mkmuniz/vedei/detect"
)

// confidenceRank orders confidence so a threshold can be compared.
var confidenceRank = map[detect.Confidence]int{
	detect.ConfidenceLow:    0,
	detect.ConfidenceMedium: 1,
	detect.ConfidenceHigh:   2,
}

// parseConfidence validates a --min-confidence value.
func parseConfidence(s string) (detect.Confidence, error) {
	c := detect.Confidence(s)
	if _, ok := confidenceRank[c]; !ok {
		return "", fmt.Errorf("unknown confidence %q, want low, medium or high", s)
	}
	return c, nil
}

// atLeast keeps the findings at or above min.
//
// A finding with no confidence set is kept: an engine that did not classify is
// not the same as an engine that classified it as unlikely, and dropping it
// would hide findings by accident.
func atLeast(findings []detect.Finding, min detect.Confidence) []detect.Finding {
	if confidenceRank[min] == 0 {
		return findings
	}
	kept := make([]detect.Finding, 0, len(findings))
	for _, f := range findings {
		rank, known := confidenceRank[f.Confidence]
		if !known || rank >= confidenceRank[min] {
			kept = append(kept, f)
		}
	}
	return kept
}
