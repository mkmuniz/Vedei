package br

// CNHLength is the number of digits in a CNH registration number.
const CNHLength = 11

// cnhCheckDigits computes both check digits of a CNH from its nine-digit base,
// following the DENATRAN mod-11 variant.
//
// Two details separate it from CPF and trip most implementations:
// the weights run 9..1 for the first digit and 1..9 for the second, and when
// the first digit overflows past 9 it collapses to 0 while shifting the
// second by two. The overflow clamp on the second digit is applied after that
// shift, not before — doing it in the other order can yield 10, which is not
// representable.
func cnhCheckDigits(base string) (int, int) {
	sum := 0
	for i, w := 0, 9; i < 9; i, w = i+1, w-1 {
		sum += int(base[i]-'0') * w
	}
	dv1 := sum % 11
	shifted := false
	if dv1 > 9 {
		dv1, shifted = 0, true
	}

	sum = 0
	for i, w := 0, 1; i < 9; i, w = i+1, w+1 {
		sum += int(base[i]-'0') * w
	}
	dv2 := sum % 11
	if shifted {
		if dv2-2 < 0 {
			dv2 += 9
		} else {
			dv2 -= 2
		}
	}
	if dv2 > 9 {
		dv2 = 0
	}

	return dv1, dv2
}

// ValidateCNH reports whether s is a structurally valid CNH (the driver's
// licence registration number, which stays with the holder for life).
//
// Structure only; see docs/adr/002-offline-validation.md.
func ValidateCNH(s string) bool {
	d := onlyDigits(s)
	if len(d) != CNHLength || allSameDigit(d) {
		return false
	}
	dv1, dv2 := cnhCheckDigits(d[:9])
	return int(d[9]-'0') == dv1 && int(d[10]-'0') == dv2
}
