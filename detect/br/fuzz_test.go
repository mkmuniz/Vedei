package br

import (
	"strings"
	"testing"
)

// Fuzzing belongs here more than anywhere else in the project. Check-digit
// arithmetic is a small amount of code with a large input space, reached by
// text nadzor does not control, and its failure modes are quiet: a validator
// that accepts one wrong value leaks, and one that rejects a right value hides.
// Examples find neither. The targets below state properties instead.

// fuzzSeeds are the shapes worth starting from: real documents, the masks they
// circulate in, and the inputs that have broken something before.
var fuzzSeeds = []string{
	"529.982.247-25",
	"52998224725",
	"11.222.333/0001-81",
	"12.ABC.345/01DE-35",
	"4539 5787 6362 1486",
	"f47ac10b-58cc-4372-a567-0e02b2c3d479",
	"11111111-2222-3333-4444-555555555555", // read as a card once
	"v0.0.0-20240915155400-7ee5256398cf",   // read as a card once
	"+5511987654321",
	"E12345678202301011200abcdefghijk",
	"",
	"0",
	strings.Repeat("9", 500),
	strings.Repeat("0", 11),
	"\x00\xff\xfe",
	"日本語のテキスト",
}

// digitsFrom turns arbitrary fuzz input into exactly n digits, so the fuzzer
// explores the space of documents rather than the much larger space of strings
// that are not documents at all.
func digitsFrom(s string, n int) string {
	var b strings.Builder
	b.Grow(n)
	for i := 0; i < len(s) && b.Len() < n; i++ {
		if s[i] >= '0' && s[i] <= '9' {
			b.WriteByte(s[i])
		}
	}
	// Pad deterministically rather than rejecting: rejecting throws away most
	// of the fuzzer's inputs, and padding keeps the mutation it found.
	for b.Len() < n {
		b.WriteByte('0' + byte(b.Len()%7))
	}
	return b.String()
}

// FuzzValidatorsNeverPanic is the floor. Every one of these takes text from a
// file, a log line or an agent transcript, and a panic on the reporting path is
// a failed scan while a panic on the redaction path is a broken session.
func FuzzValidatorsNeverPanic(f *testing.F) {
	for _, s := range fuzzSeeds {
		f.Add(s)
	}
	f.Fuzz(func(_ *testing.T, s string) {
		ValidateCPF(s)
		ValidateCIN(s)
		ValidateCNPJ(s)
		ValidateCNH(s)
		ValidatePIS(s)
		ValidateTituloEleitor(s)
		ValidateCNS(s)
		ValidateLuhn(s)
		DetectCardBrand(s)
		ClassifyPixKey(s)
		ValidateChavePix(s)
		ValidateE2EID(s)
		ParseE2EID(s)
		LookupISPB(s)
		Extract(s)
		ExtractPixKeys(s)
	})
}

// FuzzExtractYieldsOnlyValidValues is the invariant that holds the extractor
// and the validators together.
//
// Every match must satisfy its own validator, its offsets must select exactly
// the value it reports, and no two matches may overlap. The last one matters
// because the redaction path rewrites by offset: overlapping spans mean a
// replacement lands inside another replacement.
func FuzzExtractYieldsOnlyValidValues(f *testing.F) {
	for _, s := range fuzzSeeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		matches := append(Extract(s), ExtractPixKeys(s)...)

		for _, m := range matches {
			if m.Start < 0 || m.End > len(s) || m.Start >= m.End {
				t.Fatalf("offsets out of range: %+v for an input of %d bytes", m, len(s))
			}
			if s[m.Start:m.End] != m.Value {
				t.Fatalf("offsets select %q, but Value is %q", s[m.Start:m.End], m.Value)
			}
			if !validate(m.Kind, m.Value) {
				t.Fatalf("%s %q was extracted but does not validate", m.Kind, m.Value)
			}
		}

		for i := range matches {
			for j := i + 1; j < len(matches); j++ {
				a, b := matches[i], matches[j]
				if a.Start < b.End && b.Start < a.End {
					t.Fatalf("overlapping matches: %+v and %+v", a, b)
				}
			}
		}
	})
}

// FuzzExtractIsDeterministic guards a property the report formats depend on:
// two runs over the same bytes must produce the same findings, or a diff of two
// reports is unreadable and a fingerprint is not stable.
func FuzzExtractIsDeterministic(f *testing.F) {
	for _, s := range fuzzSeeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		a, b := Extract(s), Extract(s)
		if len(a) != len(b) {
			t.Fatalf("two runs found %d and %d matches", len(a), len(b))
		}
		for i := range a {
			if a[i] != b[i] {
				t.Fatalf("match %d differs between runs: %+v and %+v", i, a[i], b[i])
			}
		}
	})
}

// FuzzCPFCheckDigits drives the arithmetic directly: the fuzzer supplies the
// nine base digits, the check digits are computed independently of the
// validator, and the result must validate.
//
// The corruption half carries a lesson that cost a wrong test once. Changing
// one digit does not always break a mod-11 document, because remainders 0 and 1
// both map to a check digit of 0. So a corrupted value that still validates is
// only a bug if an independent recomputation disagrees with the validator.
func FuzzCPFCheckDigits(f *testing.F) {
	f.Add("529982247", 0)
	f.Add("111222333", 3)
	f.Add("000000001", 10)
	f.Fuzz(func(t *testing.T, seed string, pos int) {
		base := digitsFrom(seed, 9)
		if allSame(base) {
			// Repeated sequences are invalid by rule, so the generator would
			// contradict the validator here rather than test it.
			return
		}

		d1, d2 := expectedCPFCheckDigits(base)
		cpf := base + string(rune('0'+d1)) + string(rune('0'+d2))

		if !ValidateCPF(cpf) {
			t.Fatalf("a CPF built from independently computed check digits was rejected: %s", cpf)
		}

		// Punctuation must not change the answer.
		for _, m := range masks(cpf) {
			if !ValidateCPF(m) {
				t.Fatalf("the mask %q of a valid CPF was rejected", m)
			}
		}

		// Now change one digit and hold the validator to an independent count.
		if pos < 0 {
			pos = -pos
		}
		i := pos % 11
		b := []byte(cpf)
		b[i] = '0' + (b[i]-'0'+1)%10
		changed := string(b)

		w1, w2 := expectedCPFCheckDigits(changed)
		shouldPass := !allSame(changed) &&
			int(changed[9]-'0') == w1 && int(changed[10]-'0') == w2

		if got := ValidateCPF(changed); got != shouldPass {
			t.Fatalf("ValidateCPF(%s) = %v, but recomputing the digits gives %d%d",
				changed, got, w1, w2)
		}
	})
}

// FuzzCNPJCheckDigits does the same for both CNPJ formats. The alphanumeric one
// takes effect on 2026-07-06 and its weighting reads a letter as its ASCII code
// minus 48, which is the part most likely to be got wrong.
func FuzzCNPJCheckDigits(f *testing.F) {
	f.Add("112223330001", false)
	f.Add("12ABC34501DE", true)
	f.Fuzz(func(t *testing.T, seed string, alpha bool) {
		base := cnpjBaseFrom(seed, alpha)
		if allSame(base) {
			return
		}

		d1, d2 := expectedCNPJCheckDigits(base)
		cnpj := base + string(rune('0'+d1)) + string(rune('0'+d2))

		if !ValidateCNPJ(cnpj) {
			t.Fatalf("a CNPJ built from independently computed check digits was rejected: %s", cnpj)
		}
		// Case must not matter for the alphanumeric form: a document is written
		// in whatever case its author felt like.
		if alpha && !ValidateCNPJ(strings.ToLower(cnpj)) {
			t.Fatalf("a lower-cased alphanumeric CNPJ was rejected: %s", cnpj)
		}
	})
}

// cnpjBaseFrom turns fuzz input into twelve positions of the right alphabet.
func cnpjBaseFrom(s string, alpha bool) string {
	if !alpha {
		return digitsFrom(s, 12)
	}
	var b strings.Builder
	b.Grow(12)
	for i := 0; i < len(s) && b.Len() < 12; i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9', c >= 'A' && c <= 'Z':
			b.WriteByte(c)
		case c >= 'a' && c <= 'z':
			b.WriteByte(c - 32)
		}
	}
	for b.Len() < 12 {
		b.WriteByte(cnpjAlphabet[b.Len()%len(cnpjAlphabet)])
	}
	return b.String()
}

// expectedCNPJCheckDigits recomputes both digits independently of ValidateCNPJ,
// so a disagreement names which of the two is wrong.
func expectedCNPJCheckDigits(base string) (int, int) {
	w := [12]int{5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2}
	sum := 0
	for i := 0; i < 12; i++ {
		sum += (int(base[i]) - 48) * w[i]
	}
	d1 := mod11(sum)

	sum = (int(base[0]) - 48) * 6
	for i := 0; i < 11; i++ {
		sum += (int(base[i+1]) - 48) * w[i]
	}
	sum += d1 * 2
	return d1, mod11(sum)
}

func allSame(s string) bool {
	for i := 1; i < len(s); i++ {
		if s[i] != s[0] {
			return false
		}
	}
	return len(s) > 0
}
