package aws

import "testing"

// Keys are assembled from a prefix plus a 16-char base32 body, so the file
// carries no 20-char string that another scanner reads as a live key.
const (
	body    = "4KJ7WQZR2LMNXBTQ" // 16 base32 chars
	akiaKey = "AKIA" + body
	asiaKey = "ASIA" + body
)

func TestValidateAccessKeyID(t *testing.T) {
	for _, s := range []string{akiaKey, asiaKey} {
		if len(s) != 20 {
			t.Fatalf("test vector %q is %d chars, not 20", s, len(s))
		}
		if !ValidateAccessKeyID(s) {
			t.Errorf("valid key rejected: %s", s)
		}
	}

	invalid := map[string]string{
		"no AWS prefix":      "ABCD" + body,
		"lowercase prefix":   "akia" + body,
		"too short":          "AKIA" + body[:15],
		"too long":           "AKIA" + body + "A",
		"a 1 is not base32":  "AKIA1" + body[1:],
		"an 8 is not base32": "AKIA8" + body[1:],
		"lowercase body":     "AKIA" + "4kj7wqzr2lmnxbtq",
		"empty":              "",
	}
	for name, s := range invalid {
		if ValidateAccessKeyID(s) {
			t.Errorf("%s: accepted %q (len %d)", name, s, len(s))
		}
	}
}

func TestExtract(t *testing.T) {
	t.Run("in context", func(t *testing.T) {
		text := "AWS_ACCESS_KEY_ID=" + akiaKey + "\n"
		ms := Extract(text)
		if len(ms) != 1 {
			t.Fatalf("got %d matches, want 1", len(ms))
		}
		if ms[0].Value != akiaKey {
			t.Errorf("value = %q", ms[0].Value)
		}
		if text[ms[0].Start:ms[0].End] != akiaKey {
			t.Errorf("offsets select %q, not the key", text[ms[0].Start:ms[0].End])
		}
	})

	t.Run("two on one line", func(t *testing.T) {
		if ms := Extract(akiaKey + " " + asiaKey); len(ms) != 2 {
			t.Fatalf("got %d, want 2", len(ms))
		}
	})

	t.Run("a longer token is not a key", func(t *testing.T) {
		if ms := Extract("X" + akiaKey + "Y"); len(ms) != 0 {
			t.Errorf("a fragment of a longer token was matched: %+v", ms)
		}
		if ms := Extract(akiaKey + "EXTRA"); len(ms) != 0 {
			t.Errorf("a key followed by more base32 was matched: %+v", ms)
		}
	})

	t.Run("nothing to find", func(t *testing.T) {
		if ms := Extract("the quick brown fox AKIA jumped"); len(ms) != 0 {
			t.Errorf("matched something in prose: %+v", ms)
		}
	})
}

func TestExtract_RejectsNonAWSPrefix(t *testing.T) {
	for _, s := range []string{"ABCD" + body, "ZZZZ" + body} {
		if ms := Extract(s); len(ms) != 0 {
			t.Errorf("%q matched despite a non-AWS prefix", s)
		}
	}
}
