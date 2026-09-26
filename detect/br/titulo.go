package br

// TituloLength is the number of digits in a voter registration number.
const TituloLength = 12

// ValidateTituloEleitor reports whether s is a structurally valid título de
// eleitor.
//
// Digits 9 and 10 carry the issuing state code, valid from 01 to 28, so the
// number encodes where it was issued. The two check digits use mod 11 with a
// remainder of 10 collapsing to 0. Structure only.
func ValidateTituloEleitor(s string) bool {
	d := onlyDigits(s)
	if len(d) != TituloLength || allSameDigit(d) {
		return false
	}

	uf := int(d[8]-'0')*10 + int(d[9]-'0')
	if uf < 1 || uf > 28 {
		return false
	}

	sum := 0
	for i, w := 0, 2; i < 8; i, w = i+1, w+1 {
		sum += int(d[i]-'0') * w
	}
	d1 := sum % 11
	if d1 >= 10 {
		d1 = 0
	}
	if int(d[10]-'0') != d1 {
		return false
	}

	sum = int(d[8]-'0')*7 + int(d[9]-'0')*8 + d1*9
	d2 := sum % 11
	if d2 >= 10 {
		d2 = 0
	}
	return int(d[11]-'0') == d2
}
