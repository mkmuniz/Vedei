package redact

import "strings"

// Mask hides a value while keeping its shape, so a reader can tell what kind
// of thing was there and match it against what they expected, without the
// value itself being readable.
//
// The last two characters survive. That is enough for a human to confirm
// "yes, that is the CPF I was looking at" and far too little to reconstruct
// the number: for a CPF those two characters are the check digits, which are
// derived from the other nine and carry no independent information.
func Mask(s string) string {
	if s == "" {
		return ""
	}

	runes := []rune(s)
	const keep = 2

	var b strings.Builder
	b.Grow(len(s))
	for i, r := range runes {
		switch {
		case i >= len(runes)-keep:
			b.WriteRune(r)
		case isStructural(r):
			b.WriteRune(r)
		default:
			b.WriteRune('*')
		}
	}
	return b.String()
}

// isStructural reports whether a rune is punctuation that gives the value its
// recognizable shape rather than carrying information.
func isStructural(r rune) bool {
	switch r {
	case '.', '-', '/', ' ', '@', '+', '_':
		return true
	default:
		return false
	}
}
