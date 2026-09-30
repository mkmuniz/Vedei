// Package fingerprint computes a stable identifier for a finding.
package fingerprint

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// Length is the number of hex characters in a fingerprint. Sixteen bytes of
// SHA-256 is far more than enough to avoid collisions in one repository,
// and short enough to paste into an ignore file by hand.
const Length = 32

// Of returns the fingerprint of a finding, derived from its type and the
// normalized value — never from its location.
//
// That choice is deliberate: an entry in .vedeiignore must survive the file
// being moved, renamed, or having lines inserted above it. Fingerprinting the
// location instead is what makes ignore files rot.
//
// Normalization strips the punctuation a Brazilian document circulates with,
// so 123.456.789-09 and 12345678909 fingerprint identically, and upper-cases
// letters so an alphanumeric CNPJ matches whatever case it was written in.
func Of(findingType, value string) string {
	h := sha256.Sum256([]byte(findingType + "\x00" + normalize(value)))
	return hex.EncodeToString(h[:])[:Length]
}

func normalize(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9', r >= 'A' && r <= 'Z':
			b.WriteRune(r)
		case r >= 'a' && r <= 'z':
			b.WriteRune(r - 32)
		}
	}
	return b.String()
}
