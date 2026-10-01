// Package aws detects AWS credentials that the upstream secret corpus misses.
//
// It exists because of a measurement, not a hunch: betterleaks, which vedei
// relies on for secrets (ADR-001), reports nothing for an AWS access key id —
// not bare, not with an "AWS_ACCESS_KEY_ID=" context, not for ASIA either. An
// access key id in a log or a transcript is exactly the kind of thing vedei is
// meant to keep out of an agent's context, so this is a gap worth a rule of its
// own. It is the only detection logic vedei owns outside the Brazilian core.
//
// Only the two credential-bearing prefixes are matched. AKIA is a long-term
// access key and ASIA a temporary one from STS; both pair with a secret access
// key and are what leaks. The other documented prefixes — AIDA, AROA, AGPA and
// so on — are unique ids for IAM resources, not secrets, so matching them would
// be noise.
package aws

import "regexp"

// Match is one detected value and where it sits in the scanned text.
type Match struct {
	Value string
	Start int // byte offset of the first character
	End   int // byte offset just past the last
}

// AccessKeyID is the finding type vedei reports these under.
const AccessKeyID = "aws-access-key-id"

// accessKeyRe matches an access key id: a 4-character prefix, then 16 base32
// characters.
//
// base32 is A–Z and 2–7 — it has no 0, 1, 8 or 9. That is a real structural
// check, not a shape: a 20-character run that contains one of those digits after
// the prefix is not an access key id, which rules out most lookalikes for free.
// The surrounding negative lookahead-substitutes keep a longer alphanumeric
// token (a hash, a longer id) from yielding a 20-character fragment.
var accessKeyRe = regexp.MustCompile(`(?:AKIA|ASIA)[A-Z2-7]{16}`)

// ValidateAccessKeyID reports whether s is structurally a valid AWS access key
// id: a known credential prefix followed by sixteen base32 characters.
//
// Structural, never live. Like a CPF whose check digits close, this says the
// value is well-formed, not that the key still works — confirming that means
// calling AWS, which is M9. AWS access key ids also encode the account id with a
// checksum, which a future revision could verify to raise confidence and surface
// the account; it is deliberately not invented here.
func ValidateAccessKeyID(s string) bool {
	if len(s) != 20 {
		return false
	}
	loc := accessKeyRe.FindStringIndex(s)
	return loc != nil && loc[0] == 0 && loc[1] == len(s)
}

// Extract returns every access key id in text, in order.
//
// A candidate flanked by another base32 character on either side is skipped: it
// is a slice of a longer token, not a standalone key. RE2 has no lookaround, so
// the boundary is checked after the match rather than in the pattern.
func Extract(text string) []Match {
	var out []Match
	for _, loc := range accessKeyRe.FindAllStringIndex(text, -1) {
		start, end := loc[0], loc[1]
		if !boundedLeft(text, start) || !boundedRight(text, end) {
			continue
		}
		out = append(out, Match{Value: text[start:end], Start: start, End: end})
	}
	return out
}

// boundedLeft reports whether the byte before start is not part of the token.
func boundedLeft(s string, start int) bool {
	return start == 0 || !isTokenByte(s[start-1])
}

// boundedRight reports whether the byte at end is not part of the token.
func boundedRight(s string, end int) bool {
	return end == len(s) || !isTokenByte(s[end])
}

// isTokenByte reports whether b could belong to the same identifier. A base32
// character or a digit next door means the 20-character run is a fragment of
// something longer.
func isTokenByte(b byte) bool {
	switch {
	case b >= 'A' && b <= 'Z', b >= 'a' && b <= 'z', b >= '0' && b <= '9':
		return true
	default:
		return false
	}
}
