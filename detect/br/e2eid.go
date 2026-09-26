package br

import (
	"strings"
	"time"
)

// E2EIDLength is the number of characters in a Pix end-to-end identifier.
const E2EIDLength = 32

// E2EID is a parsed Pix end-to-end identifier: the unique id every Pix
// transaction carries, present on both sides of the transfer.
type E2EID struct {
	// ISPB of the institution that originated the transaction.
	ISPB string
	// Institution is the registry entry for that ISPB, when it is known.
	Institution Institution
	// KnownInstitution is false when the ISPB is not in the registry, which
	// either means the identifier is fabricated or the institution is newer
	// than the embedded data.
	KnownInstitution bool
	// Timestamp is when the originating institution stamped the transaction.
	Timestamp time.Time
	// Sequential is the institution's own reference for the transaction.
	Sequential string
}

// ParseE2EID parses a Pix end-to-end identifier and reports whether it is
// structurally valid.
//
// The layout is E + ISPB(8) + YYYYMMDDHHMM + 11 alphanumerics. Validation
// checks the prefix, the length, that the timestamp is a real moment, and
// that the ISPB belongs to a registered institution.
//
// This is what makes a forged payment receipt detectable without contacting
// anyone: a fabricated identifier almost never carries a real ISPB, and a
// screenshot reused from another day fails the timestamp check. It proves
// the identifier is well formed — never that the money arrived. Only the
// receiving account's statement proves that.
func ParseE2EID(s string) (E2EID, bool) {
	t := strings.TrimSpace(s)
	if len(t) != E2EIDLength || (t[0] != 'E' && t[0] != 'e') {
		return E2EID{}, false
	}

	ispb := t[1:9]
	for i := 0; i < 8; i++ {
		if ispb[i] < '0' || ispb[i] > '9' {
			return E2EID{}, false
		}
	}

	ts, err := time.Parse("200601021504", t[9:21])
	if err != nil {
		return E2EID{}, false
	}

	seq := t[21:]
	for i := 0; i < len(seq); i++ {
		c := seq[i]
		isAlnum := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
		if !isAlnum {
			return E2EID{}, false
		}
	}

	inst, known := LookupISPB(ispb)
	return E2EID{
		ISPB:             ispb,
		Institution:      inst,
		KnownInstitution: known,
		Timestamp:        ts,
		Sequential:       seq,
	}, true
}

// ValidateE2EID reports whether s is a structurally valid Pix end-to-end
// identifier whose ISPB belongs to a registered institution.
func ValidateE2EID(s string) bool {
	e, ok := ParseE2EID(s)
	return ok && e.KnownInstitution
}
