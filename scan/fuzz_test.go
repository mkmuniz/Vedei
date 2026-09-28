package scan

import (
	"strings"
	"testing"
)

// The ignore matcher compiles user-supplied patterns into regular expressions.
// Two things can go wrong there and both are quiet: a pattern that panics takes
// down a scan, and a pattern that compiles into something wider than intended
// silences files nobody meant to silence. The first is a crash; the second is a
// leak that looks like a clean run.

var patternSeeds = []string{
	"*.log",
	"node_modules/",
	"/anchored.txt",
	"!negated",
	"docs/**/draft.md",
	"**",
	"**/",
	"a/**/b",
	"*.[oa]",
	"test_[!x]*.go",
	"[",
	"[]",
	"[!]",
	"[a-",
	"\\",
	"a\\",
	"!",
	"/",
	"//",
	"",
	"   ",
	"#comment",
	strings.Repeat("*", 100),
	strings.Repeat("a/", 200) + "b",
	"\x00\xff",
}

func FuzzParseIgnore(f *testing.F) {
	for _, s := range patternSeeds {
		f.Add(s, "some/path/file.go")
	}
	f.Add("*.env", ".env")
	f.Fuzz(func(t *testing.T, pattern, path string) {
		ig, err := ParseIgnore("fuzz", "", strings.NewReader(pattern))
		if err != nil {
			// A pattern that does not compile is rejected, which is the
			// intended behaviour: a rule its author believes is protecting them
			// must fail loudly rather than be skipped.
			return
		}

		// Whatever it compiled to must answer without panicking, for a file and
		// for a directory.
		ig.Match(path, false)
		ig.Match(path, true)

		// A literal pattern — no wildcard, no class, no escape, no slash — must
		// match only paths that contain it. Widening one is the failure that
		// looks like success: it silences files nobody meant to silence, and
		// the scan still reports clean.
		//
		// "?" belongs in this list. Leaving it out is what the fuzzer found,
		// with "?????" matching a five-character segment exactly as it should.
		if !strings.ContainsAny(pattern, "*?[\\/") {
			name := strings.TrimSpace(strings.TrimPrefix(strings.TrimSuffix(pattern, "/"), "!"))
			if name != "" && !strings.HasPrefix(name, "#") {
				if got, _ := ig.Match("unrelated/other/file.txt", false); got && !strings.Contains("unrelated/other/file.txt", name) {
					t.Fatalf("the literal pattern %q matched an unrelated path", pattern)
				}
			}
		}
	})
}

// FuzzIgnoreStack checks the composition rule: a deeper file wins, and a nil
// entry in the chain is the common case rather than an error.
func FuzzIgnoreStack(f *testing.F) {
	f.Add("*.log", "!keep.log", "keep.log")
	f.Add("", "", "")
	f.Add("**", "!*", "anything")
	f.Fuzz(func(t *testing.T, outer, inner, path string) {
		a, errA := ParseIgnore("outer", "", strings.NewReader(outer))
		b, errB := ParseIgnore("inner", "sub", strings.NewReader(inner))
		if errA != nil || errB != nil {
			return
		}

		st := Stack{nil, a, nil, b, nil}
		st.Ignored(path, false)
		st.Ignored(path, true)
		st.IgnoredFingerprint(path)

		// A path outside the inner file's directory must be decided by the
		// outer file alone, or a nested .gitignore reaches out of its subtree.
		if !strings.HasPrefix(path, "sub/") {
			want, _ := a.Match(path, false)
			if got := (Stack{a, b}).Ignored(path, false); got != want {
				t.Fatalf("the nested file changed the answer for %q outside its subtree", path)
			}
		}
	})
}

// FuzzIsBinary is the gate deciding whether content is scanned at all. A false
// positive here skips a file silently, which is the worst kind of miss.
func FuzzIsBinary(f *testing.F) {
	f.Add([]byte("plain text"))
	f.Add([]byte("with a nul \x00 inside"))
	f.Add([]byte{})
	f.Add([]byte("日本語"))
	f.Fuzz(func(t *testing.T, content []byte) {
		got := isBinary(content)

		// The rule is exactly "a NUL byte in the first 8 KB", so it has to agree
		// with that statement for every input rather than approximately.
		head := content
		if len(head) > sniffLen {
			head = head[:sniffLen]
		}
		want := false
		for _, b := range head {
			if b == 0 {
				want = true
				break
			}
		}
		if got != want {
			t.Fatalf("isBinary = %v, want %v for %d bytes", got, want, len(content))
		}
	})
}
