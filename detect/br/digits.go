package br

import "strings"

// onlyDigits returns s with every non-digit rune removed. It is the first
// step of every validator: Brazilian documents circulate with several masks
// (123.456.789-09, 123 456 789 09, 12345678909) and all of them are the same
// number.
func onlyDigits(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r >= '0' && r <= '9' {
			b.WriteByte(byte(r))
		}
	}
	return b.String()
}

// allSameDigit reports whether every character of s is the same digit.
//
// This matters because repeated sequences satisfy mod 11 arithmetic: 111.111.111-11
// is a "valid" CPF by the algorithm alone. Every Brazilian registry rejects
// them, and so do we.
func allSameDigit(s string) bool {
	if s == "" {
		return false
	}
	for i := 1; i < len(s); i++ {
		if s[i] != s[0] {
			return false
		}
	}
	return true
}

// mod11 computes a check digit from the weighted sum of digits, using the
// convention shared by CPF, CNH, PIS and título: a remainder below 2 yields 0.
func mod11(sum int) int {
	r := sum % 11
	if r < 2 {
		return 0
	}
	return 11 - r
}
