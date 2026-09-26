package br

// PISLength is the number of digits in a PIS/PASEP/NIS/NIT number.
const PISLength = 11

var pisWeights = [10]int{3, 2, 9, 8, 7, 6, 5, 4, 3, 2}

// ValidatePIS reports whether s is a structurally valid PIS/PASEP/NIS/NIT.
//
// The four names denote the same 11-digit number in different registries, so
// one validator serves all of them. Structure only.
func ValidatePIS(s string) bool {
	d := onlyDigits(s)
	if len(d) != PISLength || allSameDigit(d) {
		return false
	}

	sum := 0
	for i := 0; i < 10; i++ {
		sum += int(d[i]-'0') * pisWeights[i]
	}
	return int(d[10]-'0') == mod11(sum)
}
