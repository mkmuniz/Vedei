package br

import "strings"

// CNPJLength is the number of characters in a CNPJ, check digits included.
const CNPJLength = 14

// cnpjWeights are applied right-to-left over the body; the second check digit
// uses one extra leading weight of 6.
var cnpjWeights = [12]int{5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2}

// ValidateCNPJ reports whether s is a structurally valid CNPJ, in either the
// numeric or the alphanumeric format.
//
// Since 2026-07-06 the Receita Federal issues alphanumeric CNPJs: the first
// twelve positions may hold 0-9 and A-Z, while the last two remain numeric
// check digits. Letters enter the mod-11 sum as their ASCII value minus 48,
// so 'A' (65) contributes 17. Existing numeric CNPJs are unchanged, and a
// detector matching \d{14} has been wrong since that date.
//
// Structure only; see docs/adr/002-offline-validation.md.
func ValidateCNPJ(s string) bool {
	b := normalizeCNPJ(s)
	if len(b) != CNPJLength || allSameChar(b) {
		return false
	}

	// The check digits are always numeric, whatever the body holds.
	if b[12] < '0' || b[12] > '9' || b[13] < '0' || b[13] > '9' {
		return false
	}
	for i := 0; i < 12; i++ {
		if !isCNPJBodyChar(b[i]) {
			return false
		}
	}

	sum := 0
	for i := 0; i < 12; i++ {
		sum += cnpjValue(b[i]) * cnpjWeights[i]
	}
	if int(b[12]-'0') != mod11(sum) {
		return false
	}

	sum = cnpjValue(b[0]) * 6
	for i := 0; i < 12; i++ {
		sum += cnpjValue(b[i+1]) * cnpjWeights[i]
	}
	return int(b[13]-'0') == mod11(sum)
}

// cnpjValue is the numeric contribution of a CNPJ character: its ASCII code
// minus 48, which keeps digits as themselves and maps 'A'..'Z' to 17..42.
func cnpjValue(c byte) int { return int(c) - 48 }

func isCNPJBodyChar(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z')
}

// normalizeCNPJ strips punctuation and upper-cases letters, so a CNPJ written
// in any of its masks reduces to the same 14 characters.
func normalizeCNPJ(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9', r >= 'A' && r <= 'Z':
			b.WriteByte(byte(r))
		case r >= 'a' && r <= 'z':
			b.WriteByte(byte(r - 32))
		}
	}
	return b.String()
}

func allSameChar(s string) bool {
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
