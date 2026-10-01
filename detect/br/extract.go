package br

import (
	"regexp"
	"strings"
)

// Kind names a category of Brazilian sensitive data.
type Kind string

// The kinds this package can extract.
const (
	KindCPF    Kind = "cpf"
	KindCNPJ   Kind = "cnpj"
	KindCNH    Kind = "cnh"
	KindPIS    Kind = "pis"
	KindTitulo Kind = "titulo-eleitor"
	KindCNS    Kind = "cns"
	KindPAN    Kind = "card-pan"
	KindPixKey Kind = "pix-key"
	KindE2EID  Kind = "pix-e2eid"
)

// Match is one candidate found in text, before validation.
type Match struct {
	Kind  Kind
	Value string
	Start int // byte offset of the first character
	End   int // byte offset just past the last
}

// The patterns below share two rules.
//
// First, every pattern is anchored by a negative lookaround substitute: Go's
// RE2 has no lookaround, so boundaries are enforced by matching the
// surrounding byte and discarding it in a post-check rather than in the
// regex. Without that, an eleven-digit run inside a SHA-256 hash matches as
// a CPF, and hashes are everywhere in a codebase.
//
// Second, patterns accept the masks a document actually circulates in, not
// only the canonical one.
// A document's digit groups are written apart by one separator: its own
// punctuation, or a space, or a tab, or nothing. The separator classes below
// all include " \t" and none include "\s".
//
// That is a correctness fix, not only a tidy-up. CNS and título used "[\s.]",
// and \s matches a line break, so both matched a value that straddled a
// newline — the same bug the card-number pattern was already written to avoid.
// Space and tab are allowed everywhere now; "\n" is allowed nowhere. Which
// means a CPF written "529 982 247 25" is finally caught, uniformly with the
// documents that already tolerated spaces.
//
// Whether admitting a space widens false positives is a precision question, and
// it is answered by the corpus rather than guessed: a three-column table of
// three-digit numbers is the feared case, and corpus/cases has it, kept quiet by
// the check digit that a table column does not satisfy.
var patterns = []struct {
	kind Kind
	re   *regexp.Regexp
}{
	{KindE2EID, regexp.MustCompile(`[Ee][0-9]{8}[0-9]{12}[0-9A-Za-z]{11}`)},
	{KindCNPJ, regexp.MustCompile(`[0-9A-Za-z]{2}[ \t.]?[0-9A-Za-z]{3}[ \t.]?[0-9A-Za-z]{3}[ \t/]?[0-9A-Za-z]{4}[ \t-]?[0-9]{2}`)},
	{KindCNS, regexp.MustCompile(`[1-2789][0-9]{2}[ \t.]?[0-9]{4}[ \t.]?[0-9]{4}[ \t.]?[0-9]{4}`)},
	{KindTitulo, regexp.MustCompile(`[0-9]{4}[ \t.]?[0-9]{4}[ \t.]?[0-9]{4}`)},
	{KindPAN, panRe},
	{KindCPF, regexp.MustCompile(`[0-9]{3}[ \t.]?[0-9]{3}[ \t.]?[0-9]{3}[ \t.-]?[0-9]{2}`)},
	{KindPIS, regexp.MustCompile(`[0-9]{3}[ \t.]?[0-9]{5}[ \t.]?[0-9]{2}[ \t-]?[0-9]`)},
	{KindCNH, regexp.MustCompile(`[0-9]{11}`)},
}

// panRe matches a card number the way one is actually written: unbroken, or in
// groups of four with a single separator used consistently.
//
// The earlier form allowed each separator independently, which let sixteen
// digits straddle a hyphen at any position. A real run showed the cost:
// "11111111-2222-3333-4444-555555555555" — a UUID — yielded card-pan
// "4444-555555555555", at high confidence, because those sixteen digits happen
// to pass Luhn. On the agent hook that is the worst kind of error, since
// redacting an identifier the agent needed breaks the task it was doing.
//
// A tab counts as a separator because card numbers do arrive in TSV columns,
// but \s does not, because a number split across two lines is not one number.
var panRe = regexp.MustCompile(
	`[0-9]{4}[ \t][0-9]{4}[ \t][0-9]{4}[ \t][0-9]{1,7}` +
		`|[0-9]{4}-[0-9]{4}-[0-9]{4}-[0-9]{1,7}` +
		`|[0-9]{4}\.[0-9]{4}\.[0-9]{4}\.[0-9]{1,7}` +
		`|[0-9]{13,19}`)

// isBoundary reports whether b can sit next to a document without the match
// being part of a longer token. A digit or letter next door means the run is
// a fragment of something else — a hash, an id, a longer number.
func isBoundary(b byte) bool {
	switch {
	case b >= '0' && b <= '9', b >= 'a' && b <= 'z', b >= 'A' && b <= 'Z':
		return false
	case b == '_':
		return false
	default:
		return true
	}
}

// isLeftBoundary is stricter than isBoundary by one character: a "+" before a
// run of digits means a country code, so what follows is a phone number.
//
// That distinction is not cosmetic here. Every Brazilian number in E.164 form
// begins with 55, and 51 through 55 is the Mastercard issuer range — so a
// +55 phone whose digits happen to satisfy Luhn, about one in ten of them, was
// being reported as a credit card. A fuzzer found it in under two seconds with
// "+5511980198775", and it is not one unlucky number: all 89 area codes produce
// the same prefix.
//
// The asymmetry is deliberate. A "+" after a document is ordinary — a URL, a
// concatenation, a query string — so treating it as a boundary on the right
// costs nothing, while treating it as one on the left costs this.
func isLeftBoundary(b byte) bool {
	if b == '+' {
		return false
	}
	return isBoundary(b)
}

func hasBoundaries(s string, start, end int) bool {
	if start > 0 && !isLeftBoundary(s[start-1]) {
		return false
	}
	if end < len(s) && !isBoundary(s[end]) {
		return false
	}
	return true
}

// Extract returns every candidate in s that passes both the pattern and its
// validator. A candidate whose check digit fails is dropped here and never
// becomes a Finding, which is what makes "zero false positives on
// structurally invalid values" true rather than aspirational.
//
// Overlapping matches are resolved by keeping the first accepted one, with
// kinds tried in order of specificity.
const (
	// minDigits is the fewest digits a numeric document can have.
	minDigits = 11

	// An alphanumeric CNPJ may carry as few as two digits, because only its
	// check digits must be numeric — the other twelve positions can all be
	// letters. It therefore needs its own, looser gate.
	minCNPJDigits = 2
	minCNPJAlnum  = 14
)

// countChars is a single allocation-free pass returning how many digits and
// how many alphanumerics a string holds. It is the prefilter that lets most
// lines of a codebase skip the regex engine entirely.
func countChars(s string) (digits, alnum int) {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
			digits++
			alnum++
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
			alnum++
		}
	}
	return digits, alnum
}

// worthScanning reports whether a line can hold a document at all, and
// whether only the CNPJ pattern needs to run.
func worthScanning(s string) (scan, cnpjOnly bool) {
	d, a := countChars(s)
	switch {
	case d >= minDigits:
		return true, false
	case d >= minCNPJDigits && a >= minCNPJAlnum:
		return true, true
	default:
		return false, false
	}
}

// Extract returns every candidate in s that passes both the pattern and its
// validator. A candidate whose check digit fails is dropped here and never
// becomes a Finding, which is what makes "zero false positives on
// structurally invalid values" true rather than aspirational.
//
// Overlapping matches are resolved by keeping the first accepted one, with
// kinds tried in order of specificity.
//
// Text is processed line by line behind a digit-count prefilter. Running the
// seven patterns over every byte costs seven full scans; most lines of a
// codebase hold no document at all, and skipping them is worth more than any
// optimisation inside the patterns.
func Extract(s string) []Match {
	if scan, _ := worthScanning(s); !scan {
		return nil
	}

	var out []Match
	offset := 0
	for offset <= len(s) {
		end := strings.IndexByte(s[offset:], '\n')
		var line string
		if end < 0 {
			line, end = s[offset:], len(s)-offset
		} else {
			line = s[offset : offset+end]
		}

		if scan, cnpjOnly := worthScanning(line); scan {
			for _, m := range extractLine(line, cnpjOnly) {
				m.Start += offset
				m.End += offset
				out = append(out, m)
			}
		}
		offset += end + 1
	}
	return out
}

// extractLine runs the patterns over a single line already known to hold
// enough digits to be worth the cost.
func extractLine(s string, cnpjOnly bool) []Match {
	var out []Match
	var taken []bool

	for _, p := range patterns {
		if cnpjOnly && p.kind != KindCNPJ {
			continue
		}
		for _, loc := range p.re.FindAllStringIndex(s, -1) {
			start, end := loc[0], loc[1]
			if !hasBoundaries(s, start, end) {
				continue
			}
			if taken != nil && overlaps(taken, start, end) {
				continue
			}
			v := s[start:end]
			if !validate(p.kind, v) {
				continue
			}
			if taken == nil {
				taken = make([]bool, len(s)+1)
			}
			out = append(out, Match{Kind: p.kind, Value: v, Start: start, End: end})
			for i := start; i < end; i++ {
				taken[i] = true
			}
		}
	}
	return out
}

func overlaps(taken []bool, start, end int) bool {
	for i := start; i < end; i++ {
		if taken[i] {
			return true
		}
	}
	return false
}

// validate dispatches a candidate to the validator for its kind.
// validatePAN accepts a card number, and rejects the thing that looks most like
// one and is not: a timestamp.
//
// Luhn passes on a random digit run roughly one time in ten, and unbroken runs
// of 13 to 19 digits are everywhere. Scanning vedei's own repository found
// "20240915155400" in go.mod — the timestamp inside a Go pseudo-version —
// reported as a card at high confidence. YYYYMMDDHHMMSS appears in module
// versions, log lines, filenames and migration names, so this is a whole class
// of false positive rather than one unlucky number.
//
// So an unbroken run must also begin with a recognized issuer range. Every real
// card does, and a timestamp does not: no network issues numbers starting 19, 20
// or 21. A number written in groups of four is exempt, because that formatting
// is itself the evidence — nobody writes a timestamp as "2024 0915 1554 00".
func validatePAN(v string) bool {
	if !ValidateLuhn(v) {
		return false
	}
	if hasGroupSeparators(v) {
		return true
	}
	return DetectCardBrand(v) != BrandUnknown
}

// hasGroupSeparators reports whether the value was written in groups rather than
// as one unbroken run.
func hasGroupSeparators(v string) bool {
	for i := 0; i < len(v); i++ {
		switch v[i] {
		case ' ', '\t', '-', '.':
			return true
		}
	}
	return false
}

func validate(k Kind, v string) bool {
	switch k {
	case KindCPF:
		return ValidateCPF(v)
	case KindCNPJ:
		// The CNPJ pattern also matches a bare 14-digit run; require that the
		// value is not plausibly something else before accepting it.
		return ValidateCNPJ(v)
	case KindCNH:
		return ValidateCNH(v)
	case KindPIS:
		return ValidatePIS(v)
	case KindTitulo:
		return ValidateTituloEleitor(v)
	case KindCNS:
		return ValidateCNS(v)
	case KindPAN:
		return validatePAN(v)
	case KindPixKey:
		return ValidateChavePix(v)
	case KindE2EID:
		return ValidateE2EID(v)
	default:
		return false
	}
}

// Pix keys that are not documents come in three shapes, each with its own
// pattern and its own cheap gate. They are kept separate rather than joined
// into one alternation because a combined regex must be run whenever any of
// the three gates opens, and the UUID gate opens on almost every line of
// real code.
var (
	pixEmailRe = regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)
	pixPhoneRe = regexp.MustCompile(`\+55[0-9]{10,11}`)
	pixEVPRe   = regexp.MustCompile(`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}`)
)

// mayHoldUUID reports whether a line contains the start of a UUID: eight hex
// digits, a hyphen, four hex digits, another hyphen.
//
// Counting hyphens is not enough. A UUID has four, but so does
// "const my-var-name = other-thing-here", and kebab-case is everywhere in
// source. Checking the layout instead costs one pass and closes the gate on
// ordinary code, which is the difference between the pattern running on
// every line of a repository and running on almost none.
func mayHoldUUID(s string) bool {
	for i := 8; i+5 < len(s); i++ {
		if s[i] != '-' || s[i+5] != '-' {
			continue
		}
		if isHexRun(s[i-8:i]) && isHexRun(s[i+1:i+5]) {
			return true
		}
	}
	return false
}

func isHexRun(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		isHex := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
		if !isHex {
			return false
		}
	}
	return true
}

// ExtractPixKeys returns the email, phone and EVP Pix keys in s. CPF and
// CNPJ keys are found by their own document extractors.
//
// Each pattern runs only on lines that could possibly match it. Without
// this, the regexes cost 11 MB/s against 538 MB/s for the document
// patterns — slow enough to be a denial-of-service opening for anything
// scanning attacker-supplied content.
func ExtractPixKeys(s string) []Match {
	var out []Match
	offset := 0

	for offset <= len(s) {
		end := strings.IndexByte(s[offset:], '\n')
		var line string
		if end < 0 {
			line, end = s[offset:], len(s)-offset
		} else {
			line = s[offset : offset+end]
		}

		out = appendPixMatches(out, line, offset)
		offset += end + 1
	}
	return out
}

// pixContextWords are the words that turn an ambiguous string into evidence
// of a Pix key.
var pixContextWords = []string{"pix", "chave", "recebedor", "favorecido", "transferencia", "transferência"}

// hasPixContext reports whether a line mentions Pix near the match.
//
// This exists because of what the first real run showed. Auditing 29 agent
// transcripts produced 17,823 findings, of which 17,690 were "Pix keys" that
// were actually UUIDs: session ids, message ids, tool-call ids. A UUID v4 is
// a valid EVP key by format and almost never one in practice, and the same
// is true of an email address. Reporting them all is not thorough, it is
// noise that makes the tool unusable.
//
// A phone key is exempt: "+55" followed by a valid area code and eight or
// nine digits is specific enough to stand alone.
func hasPixContext(line string) bool {
	lower := strings.ToLower(line)
	for _, w := range pixContextWords {
		if strings.Contains(lower, w) {
			return true
		}
	}
	return false
}

func appendPixMatches(out []Match, line string, offset int) []Match {
	// Email and EVP shapes are ambiguous on their own and need context.
	// Checking it once is cheaper than running either pattern.
	ambiguousOK := hasPixContext(line)

	if ambiguousOK && strings.IndexByte(line, '@') >= 0 {
		out = collect(out, pixEmailRe, line, offset)
	}
	if strings.Contains(line, "+55") {
		out = collect(out, pixPhoneRe, line, offset)
	}
	if ambiguousOK && mayHoldUUID(line) {
		out = collect(out, pixEVPRe, line, offset)
	}
	return out
}

func collect(out []Match, re *regexp.Regexp, line string, offset int) []Match {
	for _, loc := range re.FindAllStringIndex(line, -1) {
		v := line[loc[0]:loc[1]]
		if !ValidateChavePix(strings.TrimSpace(v)) {
			continue
		}
		out = append(out, Match{
			Kind:  KindPixKey,
			Value: v,
			Start: offset + loc[0],
			End:   offset + loc[1],
		})
	}
	return out
}
