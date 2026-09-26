package br

// ValidateLuhn reports whether s satisfies the Luhn checksum, the algorithm
// every card network uses for the primary account number (PAN).
//
// A PAN is 13 to 19 digits. Luhn catches every single-digit error and most
// transpositions, but it is a checksum, not proof that the card exists.
func ValidateLuhn(s string) bool {
	d := onlyDigits(s)
	if len(d) < 13 || len(d) > 19 {
		return false
	}

	sum, double := 0, false
	for i := len(d) - 1; i >= 0; i-- {
		n := int(d[i] - '0')
		if double {
			if n *= 2; n > 9 {
				n -= 9
			}
		}
		sum += n
		double = !double
	}
	return sum%10 == 0
}

// CardBrand names the network a PAN belongs to, inferred from its BIN range.
type CardBrand string

// The card networks nadzor recognizes by BIN range.
const (
	BrandUnknown    CardBrand = "unknown"
	BrandVisa       CardBrand = "visa"
	BrandMastercard CardBrand = "mastercard"
	BrandAmex       CardBrand = "amex"
	BrandElo        CardBrand = "elo"
	BrandHipercard  CardBrand = "hipercard"
	BrandDiners     CardBrand = "diners"
)

// DetectCardBrand returns the network a PAN appears to belong to. Elo and
// Hipercard are Brazilian networks absent from most international lists,
// which is why they are handled here.
func DetectCardBrand(s string) CardBrand {
	d := onlyDigits(s)
	if len(d) < 6 {
		return BrandUnknown
	}
	p2, p4, p6 := d[:2], d[:4], d[:6]

	switch {
	case d[0] == '4':
		return BrandVisa
	case p2 >= "51" && p2 <= "55", p4 >= "2221" && p4 <= "2720":
		return BrandMastercard
	case p2 == "34", p2 == "37":
		return BrandAmex
	case p6 == "606282", p6 == "637095", p4 == "5067", p4 == "4576":
		return BrandElo
	case p4 == "6062":
		return BrandHipercard
	case p2 == "36", p4 == "3095", p2 == "38", p2 == "39":
		return BrandDiners
	default:
		return BrandUnknown
	}
}
