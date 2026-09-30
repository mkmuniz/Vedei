package transcript

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/mkmuniz/vedei/detect"
)

// scrubRecord is the highest-blast-radius function in the project: it rewrites
// a file the user cannot get back, from input the user did not write, and a bug
// in it corrupts session history rather than merely missing a finding.
//
// It also parses. Anything that parses untrusted input and re-emits it belongs
// under a fuzzer.

var recordSeeds = []string{
	`{"type":"user","message":{"content":"cpf 529.982.247-25"}}`,
	`{"ts":1759000000123,"cost":0.00012345,"big":123456789012345678}`,
	`{"a":[{"b":[["nested"]]}],"n":null,"t":true,"f":false}`,
	`{"escapes":"linha\nlinha\t\"aspas\" <tag> ação 日本 \\ \u0000"}`,
	`{"":""}`,
	`{}`,
	`[]`,
	`[1,2,3]`,
	`"a bare string"`,
	`null`,
	`123`,
	`not json at all`,
	`{"unterminated": `,
	`{} {"trailing":"tokens"}`,
	``,
	`   `,
	"\x00\xff",
}

// keepAll changes nothing, which isolates the rewriter: any difference between
// input and output is then the rewriter's doing, not the detector's.
func keepAll(s string) (string, []detect.Finding, bool) { return s, nil, false }

// replaceAll stands in for a detector that matched, since a replacement is
// where an escaping bug shows up.
func replaceAll(with string) redactor {
	return func(string) (string, []detect.Finding, bool) { return with, nil, true }
}

// FuzzScrubRecord_PreservesMeaning is the property that matters: for input that
// is valid JSON, the output must be valid JSON that decodes to the same value.
//
// "The same value" and not "the same bytes": the rewriter re-emits the document,
// so whitespace between tokens is not preserved. Everything a consumer can
// observe — key order, number text, string contents — is.
func FuzzScrubRecord_PreservesMeaning(f *testing.F) {
	for _, s := range recordSeeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		line := strings.ReplaceAll(s, "\n", " ")

		out, _, err := scrubRecord([]byte(line), keepAll)
		if err != nil {
			t.Fatalf("scrubRecord returned an error for %q: %v", line, err)
		}

		// A record that was not valid JSON is passed through as text, and the
		// rewriter must not have invented structure around it.
		//
		// The gate is json.Valid on the whole line, which is what the code
		// uses. strings.TrimSpace is not the same test: it trims \v and \f,
		// which JSON does not accept as whitespace, so "0\v" looked valid here
		// and was not. The fuzzer found that too.
		if !json.Valid([]byte(line)) {
			if string(out) != line {
				t.Fatalf("a non-JSON record was altered:\n got %q\nwant %q", out, line)
			}
			return
		}

		if !json.Valid(out) {
			t.Fatalf("valid JSON in, invalid JSON out:\n in  %q\n out %q", line, out)
		}

		// Decoded with UseNumber on both sides. Plain json.Unmarshal into any
		// turns every number into a float64, and a 300-digit integer then fails
		// to decode at all — which is the same trap the rewriter avoids, and
		// the fuzzer walked the test into it.
		before, err := decodeWithNumbers([]byte(line))
		if err != nil {
			t.Fatalf("seed is not decodable: %v", err)
		}
		after, err := decodeWithNumbers(out)
		if err != nil {
			t.Fatalf("output is not decodable: %v", err)
		}
		if !jsonEqual(before, after) {
			t.Fatalf("the value changed:\n in  %q\n out %q", line, out)
		}
	})
}

// FuzzScrubRecord_NumbersSurviveExactly guards the failure a plain decode
// causes: every number becomes a float64, which rewrites a millisecond
// timestamp into scientific notation and loses precision past 2^53.
//
// The assertion is on the number's own text, not on the whole line. The
// rewriter re-emits the document and does not preserve whitespace between
// tokens, which is stated behaviour — the fuzzer pointed that out with
// "1e00 " and it was the test that was wrong, not the code.
func FuzzScrubRecord_NumbersSurviveExactly(f *testing.F) {
	f.Add("1759000000123")
	f.Add("123456789012345678")
	f.Add("0.00012345")
	f.Add("-0")
	f.Add("1e100")
	f.Add("0")
	f.Fuzz(func(t *testing.T, numText string) {
		line := `{"n":` + numText + `}`
		if !json.Valid([]byte(line)) {
			return // the fuzzer supplied something that is not a number
		}
		// The seed has to be one bare number token, and stating that took three
		// tries — each one found by the fuzzer rather than by thinking harder:
		//
		//	""          -> {"n":""},        a string, which decodes into a Number
		//	"0"         -> {"n":"0"},       same
		//	0,"":""     -> {"n":0,"":""},   valid, but the seed is not the number
		//
		// Valid-JSON-on-its-own plus a leading digit or minus rules out all
		// three. Getting a property right is its own exercise; the fuzzer is
		// just as good at finding a wrong assertion as a wrong implementation.
		want := strings.TrimSpace(numText)
		if want == "" || (want[0] != '-' && (want[0] < '0' || want[0] > '9')) {
			return
		}
		if !json.Valid([]byte(want)) {
			return
		}

		out, _, err := scrubRecord([]byte(line), keepAll)
		if err != nil {
			t.Fatalf("scrubRecord: %v", err)
		}

		var got struct{ N json.Number }
		dec := json.NewDecoder(strings.NewReader(string(out)))
		dec.UseNumber()
		if err := dec.Decode(&got); err != nil {
			t.Fatalf("the output is not decodable: %v (%s)", err, out)
		}
		if got.N.String() != want {
			t.Fatalf("the number was rewritten: got %s, want %s", got.N, want)
		}
	})
}

// FuzzScrubRecord_RedactionKeepsItValid is the same property with a redactor
// that actually replaces, since a replacement is where an escaping bug shows up.
func FuzzScrubRecord_RedactionKeepsItValid(f *testing.F) {
	for _, s := range recordSeeds {
		f.Add(s, "X")
	}
	f.Add(`{"a":"secret"}`, `"quoted"`)
	f.Add(`{"a":"secret"}`, "line\nbreak")
	f.Add(`{"a":"secret"}`, "\x00")
	f.Fuzz(func(t *testing.T, s, replacement string) {
		line := strings.ReplaceAll(s, "\n", " ")
		if !json.Valid([]byte(line)) {
			// A record that was not JSON stays not JSON, by design. Asserting
			// validity of the output would be asserting the wrong contract.
			return
		}

		out, _, err := scrubRecord([]byte(line), replaceAll(replacement))
		if err != nil {
			t.Fatalf("scrubRecord: %v", err)
		}
		if !json.Valid(out) {
			t.Fatalf("replacing with %q produced invalid JSON:\n in  %q\n out %q",
				replacement, line, out)
		}
	})
}

// decodeWithNumbers decodes a document keeping numbers as their original text.
func decodeWithNumbers(b []byte) (any, error) {
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	return v, nil
}

// jsonEqual compares two decoded documents. Key order is checked separately by
// a unit test; here only the values matter.
func jsonEqual(a, b any) bool {
	switch x := a.(type) {
	case map[string]any:
		y, ok := b.(map[string]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for k, v := range x {
			w, present := y[k]
			if !present || !jsonEqual(v, w) {
				return false
			}
		}
		return true
	case []any:
		y, ok := b.([]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for i := range x {
			if !jsonEqual(x[i], y[i]) {
				return false
			}
		}
		return true
	default:
		return a == b
	}
}

// FuzzReadableText covers the other place untrusted JSON is walked: the reader
// that decides what text a record holds. It must not panic and must not be
// escapable by nesting, which the depth bound is there to prevent.
func FuzzReadableText(f *testing.F) {
	for _, s := range recordSeeds {
		f.Add(s)
	}
	f.Add(strings.Repeat(`{"a":`, 200) + "1" + strings.Repeat("}", 200))
	f.Add(strings.Repeat("[", 500) + strings.Repeat("]", 500))
	f.Fuzz(func(_ *testing.T, s string) {
		readableText([]byte(s))
	})
}
