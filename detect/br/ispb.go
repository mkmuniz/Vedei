package br

import (
	"bufio"
	"bytes"
	"compress/gzip"
	_ "embed"
	"strings"
	"sync"
)

// The registry is embedded rather than fetched so validation stays offline.
// See docs/adr/002-offline-validation.md: a tool that phones out to check a
// value it found in a log has leaked that value. Regenerate with
// `make update-ispb`; a new institution is recognized at the next release.
//
//go:embed assets/ispb.tsv.gz
var ispbData []byte

// Institution is a financial institution as the Banco Central registers it.
type Institution struct {
	// ISPB is the eight-digit identifier used throughout the payment system.
	ISPB string
	// Name is a short form, suitable for a report line.
	Name string
	// PixType is DRCT for a direct participant, IDRT for an indirect one,
	// and empty when the institution does not take part in Pix.
	PixType string
}

var (
	ispbOnce  sync.Once
	ispbIndex map[string]Institution
)

func loadISPB() {
	ispbIndex = make(map[string]Institution, 600)

	zr, err := gzip.NewReader(bytes.NewReader(ispbData))
	if err != nil {
		return // a corrupt embedded asset leaves the registry empty, not panicking
	}
	defer func() { _ = zr.Close() }()

	sc := bufio.NewScanner(zr)
	for sc.Scan() {
		parts := strings.SplitN(sc.Text(), "\t", 3)
		if len(parts) != 3 {
			continue
		}
		ispbIndex[parts[0]] = Institution{ISPB: parts[0], Name: parts[1], PixType: parts[2]}
	}
}

// LookupISPB returns the institution registered under an eight-digit ISPB.
func LookupISPB(ispb string) (Institution, bool) {
	ispbOnce.Do(loadISPB)
	inst, ok := ispbIndex[ispb]
	return inst, ok
}

// ISPBCount returns how many institutions the embedded registry holds. It
// exists so a test can fail if the asset is ever regenerated into nothing.
func ISPBCount() int {
	ispbOnce.Do(loadISPB)
	return len(ispbIndex)
}
