package br

// CNSLength is the number of digits in a CNS (SUS health card) number.
const CNSLength = 15

// ValidateCNS reports whether s is a structurally valid CNS.
//
// Two forms exist and they are validated differently: a definitive card
// starts with 1 or 2, a provisional one with 7, 8 or 9. Both satisfy a
// weighted sum congruent to 0 modulo 11, but the definitive form derives its
// check digit from the first eleven digits. Structure only.
func ValidateCNS(s string) bool {
	d := onlyDigits(s)
	if len(d) != CNSLength {
		return false
	}

	switch d[0] {
	case '1', '2':
		return validateCNSDefinitive(d)
	case '7', '8', '9':
		return weightedSum15(d)%11 == 0
	default:
		return false
	}
}

func validateCNSDefinitive(d string) bool {
	sum := 0
	for i := 0; i < 11; i++ {
		sum += int(d[i]-'0') * (15 - i)
	}
	rest := sum % 11
	dv := 11 - rest
	if dv == 11 {
		dv = 0
	}

	// A check digit of 10 is not representable in one position, so the
	// sequence carries "001" and the digit is recomputed with an extra 2.
	if dv == 10 {
		sum += 2
		rest = sum % 11
		dv = 11 - rest
		return d[11:15] == "001"+string(rune('0'+dv))
	}
	return d[11:15] == "000"+string(rune('0'+dv))
}

func weightedSum15(d string) int {
	sum := 0
	for i := 0; i < 15; i++ {
		sum += int(d[i]-'0') * (15 - i)
	}
	return sum
}

// Note on the provisional form: its weights run 15 down to 1, so position
// five carries weight 11. Changing that digit shifts the weighted sum by a
// multiple of 11 and leaves it congruent to 0, which means the checksum
// cannot detect an error there. A CNS is therefore weaker evidence than a
// CPF, and confidence scoring should reflect that.
