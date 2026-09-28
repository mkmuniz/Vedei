package br

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/rand"
	"strings"
	"testing"
	"time"
)

func kindsOf(ms []Match) []Kind {
	out := make([]Kind, len(ms))
	for i, m := range ms {
		out[i] = m.Kind
	}
	return out
}

func TestExtract_FindsValidCPF(t *testing.T) {
	for _, text := range []string{
		"o cpf é 529.982.247-25 e mais nada",
		"cpf=52998224725",
		"529.982.247-25",
		"[\"529.982.247-25\"]",
	} {
		ms := Extract(text)
		if len(ms) == 0 {
			t.Errorf("no match in %q", text)
			continue
		}
		if ms[0].Kind != KindCPF {
			t.Errorf("in %q: got kind %s, want cpf", text, ms[0].Kind)
		}
	}
}

// A CPF that fails its check digit must never surface. This is the promise
// that separates nadzor from a grep.
func TestExtract_RejectsInvalidCheckDigit(t *testing.T) {
	for _, text := range []string{
		"cpf 529.982.247-26",
		"cpf 111.222.333-44",
		"000.000.000-00",
	} {
		if ms := Extract(text); len(ms) != 0 {
			t.Errorf("invalid CPF reported in %q: %+v", text, ms)
		}
	}
}

// The failure mode that matters most in a codebase: hashes contain long
// digit runs, and some of those runs are arithmetically valid documents.
func TestExtract_IgnoresDigitsInsideHashes(t *testing.T) {
	r := rand.New(rand.NewSource(100))
	hits := 0
	for i := 0; i < 5000; i++ {
		sum := sha256.Sum256([]byte(fmt.Sprintf("seed-%d", r.Int())))
		if ms := Extract(hex.EncodeToString(sum[:])); len(ms) > 0 {
			hits++
		}
	}
	if hits != 0 {
		t.Errorf("%d/5000 SHA-256 hashes produced findings; boundary check is not working", hits)
	}
}

func TestExtract_IgnoresLongerNumericTokens(t *testing.T) {
	// A valid CPF embedded in a longer run of digits is not a CPF.
	for _, text := range []string{
		"9952998224725",
		"52998224725123",
		"id_52998224725_x",
	} {
		if ms := Extract(text); len(ms) != 0 {
			t.Errorf("embedded digits reported in %q: %+v", text, ms)
		}
	}
}

func TestExtract_OffsetsPointAtTheValue(t *testing.T) {
	text := "antes 529.982.247-25 depois"
	ms := Extract(text)
	if len(ms) != 1 {
		t.Fatalf("want 1 match, got %d", len(ms))
	}
	if got := text[ms[0].Start:ms[0].End]; got != "529.982.247-25" {
		t.Errorf("offsets select %q, want the CPF", got)
	}
}

func TestExtract_FindsCNPJIncludingAlphanumeric(t *testing.T) {
	for _, text := range []string{
		"cnpj 11.222.333/0001-81",
		"cnpj 12.ABC.345/01DE-35",
	} {
		ms := Extract(text)
		if len(ms) == 0 || ms[0].Kind != KindCNPJ {
			t.Errorf("CNPJ not found in %q: %+v", text, kindsOf(ms))
		}
	}
}

func TestExtract_FindsCardPAN(t *testing.T) {
	// The forms a card number is actually written in, all Luhn-valid.
	for _, text := range []string{
		"cartao 4539 5787 6362 1486 fim",
		"cartao 4539-5787-6362-1486 fim",
		"cartao 4539.5787.6362.1486 fim",
		"cartao 4539578763621486 fim",
		"4539\t5787\t6362\t1486",
	} {
		ms := Extract(text)
		if len(ms) == 0 || ms[0].Kind != KindPAN {
			t.Errorf("PAN not found in %q: %+v", text, kindsOf(ms))
		}
	}
}

// A UUID is not a card number, and the sixteen digits inside one can pass Luhn
// by chance. This came from a real hook run, where the value was redacted at
// high confidence — on that path a false positive breaks the agent's task.
func TestExtract_UUIDIsNotACardPAN(t *testing.T) {
	for _, text := range []string{
		"11111111-2222-3333-4444-555555555555",
		"recebedor chave 11111111-2222-3333-4444-555555555555",
		"session 2ea4b13f-8fc1-4e1b-9a2c-7d5f6e8a9b01",
	} {
		for _, m := range Extract(text) {
			if m.Kind == KindPAN {
				t.Errorf("%q yielded card-pan %q", text, m.Value)
			}
		}
	}
}

// Grouping has to be consistent: a run of sixteen digits split at one
// arbitrary point is not how any card is written.
func TestExtract_RejectsInconsistentPANGrouping(t *testing.T) {
	for _, text := range []string{
		"4539-578763621486",
		"4539 5787-6362 1486",
		"4539.5787 6362.1486",
	} {
		for _, m := range Extract(text) {
			if m.Kind == KindPAN {
				t.Errorf("%q yielded card-pan %q", text, m.Value)
			}
		}
	}
}

func TestExtract_MultipleInOneText(t *testing.T) {
	text := "cpf 529.982.247-25, cnpj 11.222.333/0001-81"
	ms := Extract(text)
	if len(ms) != 2 {
		t.Fatalf("want 2 matches, got %d: %+v", len(ms), kindsOf(ms))
	}
}

func TestExtract_NoOverlappingMatches(t *testing.T) {
	text := "11.222.333/0001-81"
	ms := Extract(text)
	for i := 0; i < len(ms); i++ {
		for j := i + 1; j < len(ms); j++ {
			if ms[i].Start < ms[j].End && ms[j].Start < ms[i].End {
				t.Errorf("overlapping matches: %+v and %+v", ms[i], ms[j])
			}
		}
	}
}

func TestExtract_EmptyAndPlainText(t *testing.T) {
	for _, text := range []string{"", "nenhum dado sensivel aqui", strings.Repeat("a", 1000)} {
		if ms := Extract(text); len(ms) != 0 {
			t.Errorf("unexpected match in %q: %+v", text, ms)
		}
	}
}

func TestExtractPixKeys(t *testing.T) {
	cases := map[string]bool{
		// Email and EVP shapes need Pix context; on their own they are an
		// address and an identifier.
		"chave pix joao@exemplo.com.br":                   true,
		"pague para joao@exemplo.com.br hoje":             false,
		"chave 123e4567-e89b-42d3-a456-426614174000":      true,
		"sessionId: 123e4567-e89b-42d3-a456-426614174000": false,
		"chave pix 123e4567-e89b-12d3-a456-426614174000":  false, // not a v4 UUID
		// A phone key stands alone: "+55" plus a valid area code is specific.
		"telefone +5511987654321": true,
		"texto sem chave nenhuma": false,
	}
	for text, want := range cases {
		got := len(ExtractPixKeys(text)) > 0
		if got != want {
			t.Errorf("ExtractPixKeys(%q) found=%v, want %v", text, got, want)
		}
	}
}

func FuzzExtract(f *testing.F) {
	f.Add("cpf 529.982.247-25")
	f.Add("11.222.333/0001-81")
	f.Add(strings.Repeat("9", 500))
	f.Add("")
	f.Fuzz(func(t *testing.T, s string) {
		for _, m := range Extract(s) {
			if m.Start < 0 || m.End > len(s) || m.Start >= m.End {
				t.Fatalf("offsets out of range: %+v for input of length %d", m, len(s))
			}
			if s[m.Start:m.End] != m.Value {
				t.Fatalf("offsets do not select Value: %+v", m)
			}
		}
	})
}

func BenchmarkExtract(b *testing.B) {
	text := strings.Repeat("linha de codigo qualquer sem dado nenhum aqui\n", 50) +
		"cpf 529.982.247-25\n"
	b.SetBytes(int64(len(text)))
	for i := 0; i < b.N; i++ {
		Extract(text)
	}
}

// Throughput is a security property here, not a nicety: nadzor scans content
// it does not control, so a pattern that collapses on adversarial input is a
// denial-of-service opening. ExtractPixKeys once ran 46x slower than the
// document patterns because its alternation regex had no gate.
//
// The assertion is a ratio against Extract over the same input, not an
// absolute rate. An absolute floor is a bad test: it depends on the machine
// and on whether the race detector is on, and CI has neither the hardware
// nor the conditions a laptop does. A ratio survives both, because whatever
// slows one path slows the other.
func TestExtractPixKeys_NotCatastrophicallySlowerThanExtract(t *testing.T) {
	if testing.Short() {
		t.Skip("timing comparison skipped in short mode")
	}

	cases := []struct {
		name string
		line string
	}{
		{"prose", "linha sem nada de sensivel aqui nenhum dado\n"},
		// Kebab-case is everywhere in real source and opens the UUID gate if
		// that gate only requires a single hyphen, which was the first and
		// useless version of it.
		{"kebab case", "const my-var-name = other-thing-here;\n"},
		{"comment rules", "// ---------------------------------------\n"},
	}

	// Generous enough to absorb scheduling noise on a shared CI runner, tight
	// enough to catch the 46x regression that prompted this test.
	const maxRatio = 12.0

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			text := strings.Repeat(c.line, 50_000)

			// Warm up so neither measurement pays for first-use costs.
			Extract(text)
			ExtractPixKeys(text)

			start := time.Now()
			Extract(text)
			baseline := time.Since(start)

			start = time.Now()
			ExtractPixKeys(text)
			pix := time.Since(start)

			if baseline <= 0 {
				t.Skip("baseline too fast to measure reliably")
			}
			ratio := float64(pix) / float64(baseline)
			t.Logf("Extract %v, ExtractPixKeys %v, ratio %.1fx", baseline, pix, ratio)

			if ratio > maxRatio {
				t.Errorf("ExtractPixKeys is %.1fx slower than Extract (limit %.0fx); a gate was probably lost",
					ratio, maxRatio)
			}
		})
	}
}

// Extract must stay linear in input size. Doubling the input should roughly
// double the time; anything superlinear is a denial-of-service opening, and
// unlike a rate this holds on any machine.
func TestExtract_ScalesLinearly(t *testing.T) {
	if testing.Short() {
		t.Skip("timing comparison skipped in short mode")
	}

	line := "linha de codigo qualquer sem dado nenhum aqui\n"
	small := strings.Repeat(line, 25_000)
	large := strings.Repeat(line, 100_000) // 4x the input

	Extract(small)

	start := time.Now()
	Extract(small)
	tSmall := time.Since(start)

	start = time.Now()
	Extract(large)
	tLarge := time.Since(start)

	if tSmall <= 0 {
		t.Skip("baseline too fast to measure reliably")
	}
	ratio := float64(tLarge) / float64(tSmall)
	t.Logf("4x the input took %.1fx the time (%v -> %v)", ratio, tSmall, tLarge)

	// Linear would be 4x. Allow generous headroom for noise; quadratic on a
	// 4x input would be 16x and fails here.
	if ratio > 10 {
		t.Errorf("4x input took %.1fx the time; Extract is not scaling linearly", ratio)
	}
}

// The gate must stay closed on ordinary source and open on a real key.
// Counting hyphens was not enough: kebab-case has four of them.
func TestMayHoldUUID_GateIsTight(t *testing.T) {
	closed := []string{
		"const my-var-name = other-thing-here;",
		"// ---------------------------------------",
		"background-color: light-blue; border-top-width: 1px",
		"2026-09-26 14:30:00 -0300",
		"",
	}
	for _, s := range closed {
		if mayHoldUUID(s) {
			t.Errorf("gate opened on ordinary source: %q", s)
		}
	}

	open := []string{
		"chave 123e4567-e89b-42d3-a456-426614174000 aqui",
		"123e4567-e89b-42d3-a456-426614174000",
		"ABCDEF01-2345-4678-89AB-CDEF01234567",
	}
	for _, s := range open {
		if !mayHoldUUID(s) {
			t.Errorf("gate closed on a real UUID: %q", s)
		}
	}
}

// The regression that mattered: auditing 29 real agent transcripts produced
// 17,690 "Pix keys" that were internal UUIDs. A UUID is a valid EVP key by
// format and essentially never one in practice.
func TestExtractPixKeys_BareUUIDIsNotAPixKey(t *testing.T) {
	noise := []string{
		`{"sessionId":"33015dee-d5ac-42a1-a12b-765baa1436b1"}`,
		`  "uuid": "123e4567-e89b-42d3-a456-426614174000",`,
		"tool_use_id: 7c9e6679-7425-40de-944b-e07fc1f90ae7",
		"user joao@exemplo.com.br logged in",
		"contato: suporte@empresa.com.br",
	}
	for _, s := range noise {
		if ms := ExtractPixKeys(s); len(ms) != 0 {
			t.Errorf("reported a Pix key without context in %q: %+v", s, ms)
		}
	}

	real := []string{
		"chave pix: 123e4567-e89b-42d3-a456-426614174000",
		"a chave do recebedor e joao@exemplo.com.br",
	}
	for _, s := range real {
		if ms := ExtractPixKeys(s); len(ms) == 0 {
			t.Errorf("missed a Pix key with context in %q", s)
		}
	}
}

// A timestamp is the thing that looks most like a card number and is not. Luhn
// passes on a random digit run about one time in ten, and YYYYMMDDHHMMSS is
// everywhere: Go pseudo-versions, log lines, filenames, migration names.
//
// Every one of these passes Luhn. Scanning nadzor's own repository is where the
// first two came from — go.mod, reported at high confidence.
func TestExtract_TimestampIsNotACardPAN(t *testing.T) {
	for _, text := range []string{
		"github.com/shurcooL/graphql v0.0.0-20240915155400-7ee5256398cf",
		"go4.org v0.0.0-20260112195520-a5071408f32f",
		"migration_20240915155400_add_users.sql",
		"20240915155400",
	} {
		// Guard the premise: if Luhn stopped passing, this test would be proving
		// nothing.
		if !ValidateLuhn(text) {
			continue
		}
		for _, m := range Extract(text) {
			if m.Kind == KindPAN {
				t.Errorf("%q yielded card-pan %q", text, m.Value)
			}
		}
	}
}

// The rule that replaces "Luhn is enough": an unbroken run must also start in a
// recognized issuer range, because no network issues numbers starting 19 or 20.
func TestExtract_UnbrokenPANNeedsAnIssuerRange(t *testing.T) {
	// A Visa test number, Luhn-valid, issuer range 4.
	if ms := Extract("cartao 4539578763621486"); len(ms) == 0 || ms[0].Kind != KindPAN {
		t.Errorf("a Visa number was not found: %+v", kindsOf(ms))
	}

	// Luhn-valid, but 2024… is not an issuer range.
	for _, m := range Extract("2024091515540061") {
		if m.Kind == KindPAN {
			t.Errorf("an unbroken run outside every issuer range was accepted: %q", m.Value)
		}
	}
}

// Grouping is exempt from the issuer-range rule, because the formatting is the
// evidence: nobody writes a timestamp as "2024 0915 1554 00".
func TestExtract_GroupedPANIsAcceptedWithoutAnIssuerRange(t *testing.T) {
	// Luhn-valid and outside every issuer range, but written as a card.
	const grouped = "2024 0915 1554 0061"
	if !ValidateLuhn(grouped) {
		t.Skip("the fixture no longer passes Luhn")
	}
	found := false
	for _, m := range Extract("cartao " + grouped) {
		if m.Kind == KindPAN {
			found = true
		}
	}
	if !found {
		t.Errorf("a grouped number was rejected for its issuer range")
	}
}
