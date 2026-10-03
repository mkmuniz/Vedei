package br

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"
)

func TestCNPJ_GeneratedNumericAreValid(t *testing.T) {
	r := rand.New(rand.NewSource(10))
	for i := 0; i < genCases; i++ {
		c := genCNPJ(r, false)
		if !ValidateCNPJ(c) {
			t.Fatalf("generated numeric CNPJ rejected: %s", c)
		}
	}
}

// The alphanumeric format has been issued since 2026-07-31.
func TestCNPJ_GeneratedAlphanumericAreValid(t *testing.T) {
	r := rand.New(rand.NewSource(11))
	for i := 0; i < genCases; i++ {
		c := genCNPJ(r, true)
		if !ValidateCNPJ(c) {
			t.Fatalf("generated alphanumeric CNPJ rejected: %s", c)
		}
	}
}

func TestCNPJ_CorruptedCheckDigitFails(t *testing.T) {
	r := rand.New(rand.NewSource(12))
	for i := 0; i < genCases; i++ {
		c := []byte(genCNPJ(r, r.Intn(2) == 0))
		// Corrupt a check digit only: the body is where mod-11 collisions live.
		idx := 12 + r.Intn(2)
		orig := c[idx]
		for c[idx] == orig {
			c[idx] = byte('0' + r.Intn(10))
		}
		if ValidateCNPJ(string(c)) {
			t.Fatalf("CNPJ with wrong check digit accepted: %s", c)
		}
	}
}

func TestCNPJ_RepeatedSequencesFail(t *testing.T) {
	for _, c := range "0123456789ABZ" {
		s := strings.Repeat(string(c), 14)
		if ValidateCNPJ(s) {
			t.Errorf("repeated sequence accepted: %s", s)
		}
	}
}

func TestCNPJ_MasksAreEquivalent(t *testing.T) {
	r := rand.New(rand.NewSource(13))
	for i := 0; i < 1000; i++ {
		c := genCNPJ(r, r.Intn(2) == 0)
		masked := fmt.Sprintf("%s.%s.%s/%s-%s", c[0:2], c[2:5], c[5:8], c[8:12], c[12:14])
		if !ValidateCNPJ(masked) {
			t.Fatalf("masked CNPJ rejected: %s (plain %s)", masked, c)
		}
		if !ValidateCNPJ(strings.ToLower(c)) {
			t.Fatalf("lowercase CNPJ rejected: %s", c)
		}
	}
}

// Check digits are numeric even when the body is alphanumeric.
func TestCNPJ_LetterInCheckDigitFails(t *testing.T) {
	for _, s := range []string{"11222333000A81", "1122233300018A", "12ABC34501DE3A"} {
		if ValidateCNPJ(s) {
			t.Errorf("letter in check digit accepted: %s", s)
		}
	}
}

func TestCNPJ_Malformed(t *testing.T) {
	for _, s := range []string{"", "11222333", "112223330001812", "11.222.333/0001-8"} {
		if ValidateCNPJ(s) {
			t.Errorf("malformed input accepted: %q", s)
		}
	}
}

func TestCNPJ_KnownVectors(t *testing.T) {
	valid := []string{
		"11.222.333/0001-81",
		"00.000.000/0001-91",
		"12.ABC.345/01DE-35", // official alphanumeric example
	}
	invalid := []string{
		"11.222.333/0001-82",
		"12.ABC.345/01DE-36",
	}
	for _, s := range valid {
		if !ValidateCNPJ(s) {
			t.Errorf("known-valid CNPJ rejected: %s", s)
		}
	}
	for _, s := range invalid {
		if ValidateCNPJ(s) {
			t.Errorf("known-invalid CNPJ accepted: %s", s)
		}
	}
}

func BenchmarkValidateCNPJ(b *testing.B) {
	for i := 0; i < b.N; i++ {
		ValidateCNPJ("11.222.333/0001-81")
	}
}
