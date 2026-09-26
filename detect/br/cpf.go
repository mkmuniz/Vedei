package br

// CPFLength is the number of digits in a CPF, check digits included.
const CPFLength = 11

// ValidateCPF reports whether s is a structurally valid CPF.
//
// It accepts any of the masks a CPF circulates in and validates the two
// mod-11 check digits. It rejects the eleven repeated sequences, which the
// arithmetic alone would accept.
//
// Structure only: a valid result means the number is well formed, never that
// it was issued or whom it belongs to. See docs/adr/002-offline-validation.md.
func ValidateCPF(s string) bool {
	d := onlyDigits(s)
	if len(d) != CPFLength || allSameDigit(d) {
		return false
	}

	// First check digit: weights 10..2 over the first nine digits.
	sum := 0
	for i := 0; i < 9; i++ {
		sum += int(d[i]-'0') * (10 - i)
	}
	if int(d[9]-'0') != mod11(sum) {
		return false
	}

	// Second check digit: weights 11..2 over the first ten, so it depends on
	// the first check digit.
	sum = 0
	for i := 0; i < 10; i++ {
		sum += int(d[i]-'0') * (11 - i)
	}
	return int(d[10]-'0') == mod11(sum)
}
