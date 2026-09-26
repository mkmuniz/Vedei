package br

import (
	"math/rand"
	"strings"
	"testing"
)

// --- CNH ---

// genCNH builds a CNH with check digits correct by construction, reusing the
// production routine so the generator cannot drift from the validator.
func genCNH(r *rand.Rand) string {
	base := make([]byte, 9)
	for i := range base {
		base[i] = byte('0' + r.Intn(10))
	}
	d1, d2 := cnhCheckDigits(string(base))
	return string(base) + string(rune('0'+d1)) + string(rune('0'+d2))
}

// Vectors computed with the DENATRAN algorithm as documented, not copied
// from a third-party library. They guard against a refactor silently
// changing the arithmetic.
var cnhKnownValid = []string{"02650306461", "04661371401", "12345678900", "99999999880"}

func TestCNH_GeneratedAreValid(t *testing.T) {
	r := rand.New(rand.NewSource(19))
	for i := 0; i < genCases; i++ {
		c := genCNH(r)
		if allSameDigit(c) {
			continue
		}
		if !ValidateCNH(c) {
			t.Fatalf("generated CNH rejected: %s", c)
		}
	}
}

// Vectors produced by the published algorithm, not copied from a third party.
// They guard against a refactor silently changing the arithmetic.
func TestCNH_KnownVectors(t *testing.T) {
	for _, s := range cnhKnownValid {
		if !ValidateCNH(s) {
			t.Errorf("known-valid CNH rejected: %s", s)
		}
	}
	for _, s := range []string{"02650306462", "04661371400", "11111111111", "123"} {
		if ValidateCNH(s) {
			t.Errorf("known-invalid CNH accepted: %s", s)
		}
	}
}

func TestCNH_CorruptedCheckDigitFails(t *testing.T) {
	r := rand.New(rand.NewSource(20))
	base := "02650306461"
	for i := 0; i < 1000; i++ {
		c := []byte(base)
		idx := 9 + r.Intn(2)
		orig := c[idx]
		for c[idx] == orig {
			c[idx] = byte('0' + r.Intn(10))
		}
		if ValidateCNH(string(c)) {
			t.Fatalf("CNH with wrong check digit accepted: %s", c)
		}
	}
}

// --- PIS ---

func genPIS(r *rand.Rand) string {
	d := make([]byte, 11)
	for i := 0; i < 10; i++ {
		d[i] = byte('0' + r.Intn(10))
	}
	sum := 0
	for i := 0; i < 10; i++ {
		sum += int(d[i]-'0') * pisWeights[i]
	}
	d[10] = byte('0' + mod11(sum))
	return string(d)
}

func TestPIS_GeneratedAreValid(t *testing.T) {
	r := rand.New(rand.NewSource(21))
	for i := 0; i < genCases; i++ {
		p := genPIS(r)
		if allSameDigit(p) {
			continue
		}
		if !ValidatePIS(p) {
			t.Fatalf("generated PIS rejected: %s", p)
		}
	}
}

func TestPIS_CorruptedCheckDigitFails(t *testing.T) {
	r := rand.New(rand.NewSource(22))
	for i := 0; i < 10_000; i++ {
		p := []byte(genPIS(r))
		orig := p[10]
		for p[10] == orig {
			p[10] = byte('0' + r.Intn(10))
		}
		if ValidatePIS(string(p)) {
			t.Fatalf("PIS with wrong check digit accepted: %s", p)
		}
	}
}

func TestPIS_RepeatedFail(t *testing.T) {
	for d := '0'; d <= '9'; d++ {
		if ValidatePIS(strings.Repeat(string(d), 11)) {
			t.Errorf("repeated PIS accepted: %c", d)
		}
	}
}

// --- Título de eleitor ---

func TestTitulo_StateCodeIsChecked(t *testing.T) {
	// Digits 9-10 hold the issuing state; 00 and 29+ do not exist.
	for _, s := range []string{"123456780012", "123456782912", "123456789912"} {
		if ValidateTituloEleitor(s) {
			t.Errorf("título with invalid state code accepted: %s", s)
		}
	}
}

func TestTitulo_Malformed(t *testing.T) {
	for _, s := range []string{"", "12345", "1234567890123", "111111111111"} {
		if ValidateTituloEleitor(s) {
			t.Errorf("malformed título accepted: %q", s)
		}
	}
}

// --- Luhn and card brands ---

func TestLuhn_KnownVectors(t *testing.T) {
	valid := []string{
		"4539578763621486", // Visa test number
		"5500005555555559", // Mastercard test number
		"371449635398431",  // Amex test number
	}
	for _, s := range valid {
		if !ValidateLuhn(s) {
			t.Errorf("known-valid PAN rejected: %s", s)
		}
	}
	for _, s := range []string{"4539578763621487", "1234567812345678", "123", ""} {
		if ValidateLuhn(s) {
			t.Errorf("known-invalid PAN accepted: %s", s)
		}
	}
}

func TestLuhn_LengthBounds(t *testing.T) {
	if ValidateLuhn(strings.Repeat("0", 12)) {
		t.Error("12 digits should be too short for a PAN")
	}
	if ValidateLuhn(strings.Repeat("0", 20)) {
		t.Error("20 digits should be too long for a PAN")
	}
}

func TestDetectCardBrand(t *testing.T) {
	cases := map[string]CardBrand{
		"4539578763621486": BrandVisa,
		"5500005555555559": BrandMastercard,
		"371449635398431":  BrandAmex,
		"6062825624254001": BrandElo,
		"9999999999999999": BrandUnknown,
	}
	for pan, want := range cases {
		if got := DetectCardBrand(pan); got != want {
			t.Errorf("DetectCardBrand(%s) = %s, want %s", pan, got, want)
		}
	}
}

// --- Pix keys ---

func TestClassifyPixKey(t *testing.T) {
	cases := []struct {
		key   string
		typ   PixKeyType
		valid bool
	}{
		{"529.982.247-25", PixKeyCPF, true},
		{"529.982.247-26", PixKeyCPF, false},
		{"11.222.333/0001-81", PixKeyCNPJ, true},
		{"12.ABC.345/01DE-35", PixKeyCNPJ, true},
		{"joao@exemplo.com.br", PixKeyEmail, true},
		{"joao@", PixKeyEmail, false},
		{"+5511987654321", PixKeyPhone, true},
		{"+5501987654321", PixKeyPhone, false}, // area code cannot start with 0
		{"11987654321", PixKeyCPF, false},      // 11 digits, but not a valid CPF
		{"123e4567-e89b-42d3-a456-426614174000", PixKeyEVP, true},
		{"123e4567-e89b-12d3-a456-426614174000", PixKeyUnknown, false}, // not v4
		{"banana", PixKeyUnknown, false},
	}
	for _, c := range cases {
		typ, ok := ClassifyPixKey(c.key)
		if typ != c.typ || ok != c.valid {
			t.Errorf("ClassifyPixKey(%q) = (%s, %v), want (%s, %v)", c.key, typ, ok, c.typ, c.valid)
		}
	}
}

// --- Título: property tests ---

// genTitulo builds a título with a valid state code and correct check digits.
func genTitulo(r *rand.Rand) string {
	d := make([]byte, 12)
	for i := 0; i < 8; i++ {
		d[i] = byte('0' + r.Intn(10))
	}
	uf := 1 + r.Intn(28) // 01..28
	d[8] = byte('0' + uf/10)
	d[9] = byte('0' + uf%10)

	sum := 0
	for i, w := 0, 2; i < 8; i, w = i+1, w+1 {
		sum += int(d[i]-'0') * w
	}
	dv1 := sum % 11
	if dv1 >= 10 {
		dv1 = 0
	}
	d[10] = byte('0' + dv1)

	sum = int(d[8]-'0')*7 + int(d[9]-'0')*8 + dv1*9
	dv2 := sum % 11
	if dv2 >= 10 {
		dv2 = 0
	}
	d[11] = byte('0' + dv2)
	return string(d)
}

func TestTitulo_GeneratedAreValid(t *testing.T) {
	r := rand.New(rand.NewSource(30))
	for i := 0; i < genCases; i++ {
		s := genTitulo(r)
		if allSameDigit(s) {
			continue
		}
		if !ValidateTituloEleitor(s) {
			t.Fatalf("generated título rejected: %s", s)
		}
	}
}

func TestTitulo_CorruptedCheckDigitFails(t *testing.T) {
	r := rand.New(rand.NewSource(31))
	for i := 0; i < 10_000; i++ {
		d := []byte(genTitulo(r))
		idx := 10 + r.Intn(2)
		orig := d[idx]
		for d[idx] == orig {
			d[idx] = byte('0' + r.Intn(10))
		}
		if ValidateTituloEleitor(string(d)) {
			t.Fatalf("título with wrong check digit accepted: %s", d)
		}
	}
}

func TestTitulo_AllValidStateCodesAccepted(t *testing.T) {
	r := rand.New(rand.NewSource(32))
	seen := map[int]bool{}
	for i := 0; i < 20_000; i++ {
		s := genTitulo(r)
		uf := int(s[8]-'0')*10 + int(s[9]-'0')
		if ValidateTituloEleitor(s) {
			seen[uf] = true
		}
	}
	for uf := 1; uf <= 28; uf++ {
		if !seen[uf] {
			t.Errorf("state code %02d never accepted", uf)
		}
	}
}

// --- CNS ---

// genCNSProvisional builds a provisional CNS (starts with 7, 8 or 9) whose
// weighted sum is congruent to 0 modulo 11.
func genCNSProvisional(r *rand.Rand) string {
	for {
		d := make([]byte, 15)
		d[0] = byte('0' + 7 + r.Intn(3))
		for i := 1; i < 15; i++ {
			d[i] = byte('0' + r.Intn(10))
		}
		if weightedSum15(string(d))%11 == 0 {
			return string(d)
		}
	}
}

// genCNSDefinitive builds a definitive CNS (starts with 1 or 2) from an
// eleven-digit base plus the derived check sequence.
func genCNSDefinitive(r *rand.Rand) string {
	for {
		base := make([]byte, 11)
		base[0] = byte('0' + 1 + r.Intn(2))
		for i := 1; i < 11; i++ {
			base[i] = byte('0' + r.Intn(10))
		}

		sum := 0
		for i := 0; i < 11; i++ {
			sum += int(base[i]-'0') * (15 - i)
		}
		dv := 11 - sum%11
		if dv == 11 {
			dv = 0
		}
		if dv == 10 {
			sum += 2
			dv = 11 - sum%11
			if dv < 0 || dv > 9 {
				continue
			}
			return string(base) + "001" + string(rune('0'+dv))
		}
		return string(base) + "000" + string(rune('0'+dv))
	}
}

func TestCNS_GeneratedProvisionalAreValid(t *testing.T) {
	r := rand.New(rand.NewSource(40))
	for i := 0; i < 5_000; i++ {
		s := genCNSProvisional(r)
		if !ValidateCNS(s) {
			t.Fatalf("generated provisional CNS rejected: %s", s)
		}
	}
}

func TestCNS_GeneratedDefinitiveAreValid(t *testing.T) {
	r := rand.New(rand.NewSource(41))
	for i := 0; i < 5_000; i++ {
		s := genCNSDefinitive(r)
		if !ValidateCNS(s) {
			t.Fatalf("generated definitive CNS rejected: %s", s)
		}
	}
}

func TestCNS_CorruptedFails(t *testing.T) {
	r := rand.New(rand.NewSource(42))
	for i := 0; i < 5_000; i++ {
		d := []byte(genCNSProvisional(r))
		// Index 4 carries weight 11 and is unprotected; see the test below.
		idx := 1 + r.Intn(14)
		for idx == 4 {
			idx = 1 + r.Intn(14)
		}
		orig := d[idx]
		for d[idx] == orig {
			d[idx] = byte('0' + r.Intn(10))
		}
		if ValidateCNS(string(d)) {
			t.Fatalf("corrupted CNS accepted: %s", d)
		}
	}
}

// The provisional CNS checksum weights digits by 15 down to 1. Position five
// carries weight 11, so any change there shifts the sum by a multiple of 11
// and leaves it congruent to 0. That digit is entirely unprotected: a typo
// in it produces another "valid" CNS every time.
//
// This is a property of the scheme, not a defect here. It is asserted so the
// limitation stays visible, and so confidence scoring can account for it.
func TestCNS_Position5IsUnprotectedByDesign(t *testing.T) {
	r := rand.New(rand.NewSource(43))
	for i := 0; i < 1_000; i++ {
		d := []byte(genCNSProvisional(r))
		orig := d[4]
		for d[4] == orig {
			d[4] = byte('0' + r.Intn(10))
		}
		if !ValidateCNS(string(d)) {
			t.Fatalf("expected weight-11 position to be unprotected, but %s was rejected", d)
		}
	}
}

// A CNS must start with 1, 2, 7, 8 or 9; anything else is not a CNS.
func TestCNS_InvalidPrefixRejected(t *testing.T) {
	for _, p := range []byte{'0', '3', '4', '5', '6'} {
		s := string(p) + "00000000000000"
		if ValidateCNS(s) {
			t.Errorf("CNS with prefix %c accepted", p)
		}
	}
}

func TestCNS_Malformed(t *testing.T) {
	for _, s := range []string{"", "123", "1234567890123456"} {
		if ValidateCNS(s) {
			t.Errorf("malformed CNS accepted: %q", s)
		}
	}
}

func TestValidateChavePix(t *testing.T) {
	if !ValidateChavePix("529.982.247-25") {
		t.Error("valid CPF key rejected")
	}
	if ValidateChavePix("banana") {
		t.Error("nonsense key accepted")
	}
}
