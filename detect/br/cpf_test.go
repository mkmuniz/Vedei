package br

import (
	"math/rand"
	"strings"
	"testing"
)

const genCases = 100_000

func TestCPF_GeneratedAreValid(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	for i := 0; i < genCases; i++ {
		cpf := genCPF(r)
		if !ValidateCPF(cpf) {
			t.Fatalf("generated CPF rejected: %s", cpf)
		}
	}
}

// Corrupting one digit must be rejected — unless the corruption happens to
// produce another genuinely valid CPF. That is possible: mod 11 collapses
// remainders 0 and 1 onto check digit 0, so two different bodies can share
// check digits. The test asserts the validator agrees with an independent
// recomputation, and records how often the collision happens.
func TestCPF_CorruptedFail(t *testing.T) {
	r := rand.New(rand.NewSource(2))
	collisions := 0

	for i := 0; i < genCases; i++ {
		bad := corrupt(r, genCPF(r))
		d1, d2 := expectedCPFCheckDigits(bad)
		genuinelyValid := int(bad[9]-'0') == d1 && int(bad[10]-'0') == d2

		if got := ValidateCPF(bad); got != genuinelyValid {
			t.Fatalf("ValidateCPF(%s) = %v, recomputation says %v", bad, got, genuinelyValid)
		}
		if genuinelyValid {
			collisions++
		}
	}

	// Documented, not asserted as zero: it is a property of the algorithm.
	rate := float64(collisions) / float64(genCases) * 100
	t.Logf("single-digit corruption still valid: %d/%d (%.2f%%)", collisions, genCases, rate)

	// It must stay rare; a much higher rate would mean the validator is broken.
	if rate > 5 {
		t.Errorf("collision rate %.2f%% is too high, validator likely broken", rate)
	}
}

// The eleven repeated sequences satisfy mod 11 but are rejected by every
// Brazilian registry. This is the edge case a naive implementation misses.
func TestCPF_RepeatedSequencesFail(t *testing.T) {
	for d := '0'; d <= '9'; d++ {
		s := strings.Repeat(string(d), 11)
		if ValidateCPF(s) {
			t.Errorf("repeated sequence accepted: %s", s)
		}
	}
}

func TestCPF_MasksAreEquivalent(t *testing.T) {
	r := rand.New(rand.NewSource(3))
	for i := 0; i < 1000; i++ {
		cpf := genCPF(r)
		for _, m := range masks(cpf) {
			if !ValidateCPF(m) {
				t.Fatalf("mask rejected: %q (plain %s)", m, cpf)
			}
		}
	}
}

func TestCPF_Malformed(t *testing.T) {
	for _, s := range []string{
		"", "123", "1234567890", "123456789012",
		"abc.def.ghi-jk", "...-", "000.000.000-00",
	} {
		if ValidateCPF(s) {
			t.Errorf("malformed input accepted: %q", s)
		}
	}
}

// Published examples, to catch a generator that agrees with a broken validator.
func TestCPF_KnownVectors(t *testing.T) {
	valid := []string{"529.982.247-25", "111.444.777-35"}
	invalid := []string{"529.982.247-26", "111.444.777-30", "123.456.789-00"}

	for _, s := range valid {
		if !ValidateCPF(s) {
			t.Errorf("known-valid CPF rejected: %s", s)
		}
	}
	for _, s := range invalid {
		if ValidateCPF(s) {
			t.Errorf("known-invalid CPF accepted: %s", s)
		}
	}
}

func TestCIN_IsCPF(t *testing.T) {
	r := rand.New(rand.NewSource(4))
	for i := 0; i < 1000; i++ {
		cpf := genCPF(r)
		if ValidateCIN(cpf) != ValidateCPF(cpf) {
			t.Fatalf("CIN and CPF disagree on %s", cpf)
		}
	}
}

func BenchmarkValidateCPF(b *testing.B) {
	for i := 0; i < b.N; i++ {
		ValidateCPF("529.982.247-25")
	}
}
