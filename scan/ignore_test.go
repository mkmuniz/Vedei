package scan

import (
	"strings"
	"testing"
)

func parse(t *testing.T, dir, body string) *Ignore {
	t.Helper()
	ig, err := ParseIgnore("test", dir, strings.NewReader(body))
	if err != nil {
		t.Fatalf("ParseIgnore: %v", err)
	}
	return ig
}

func TestIgnore_Basics(t *testing.T) {
	ig := parse(t, "", `
# a comment, and a blank line above

node_modules/
*.log
/only-at-root.txt
docs/**/draft.md
build
`)

	cases := []struct {
		path  string
		isDir bool
		want  bool
	}{
		{"node_modules", true, true},
		// A directory rule silences the whole subtree, not just the directory.
		{"node_modules/pkg/index.js", false, true},
		// The same name as a file must not match a "dir/" rule.
		{"node_modules", false, false},
		// An unanchored rule matches at any depth.
		{"deep/nested/node_modules", true, true},

		{"app.log", false, true},
		{"var/logs/app.log", false, true},
		{"app.log.old", false, false},

		// A leading slash anchors to the root.
		{"only-at-root.txt", false, true},
		{"sub/only-at-root.txt", false, false},

		// "**" crosses directories; "*" does not.
		{"docs/draft.md", false, true},
		{"docs/a/b/draft.md", false, true},
		{"other/draft.md", false, false},

		// A bare name matches a file or a directory.
		{"build", true, true},
		{"build", false, true},
		{"src/build/out.o", false, true},

		{"main.go", false, false},
	}

	for _, c := range cases {
		got, _ := ig.Match(c.path, c.isDir)
		if got != c.want {
			t.Errorf("Match(%q, dir=%v) = %v, want %v", c.path, c.isDir, got, c.want)
		}
	}
}

// Negation is the reason the last matching rule wins rather than the first.
func TestIgnore_NegationTakesTheLastMatch(t *testing.T) {
	ig := parse(t, "", `
*.env
!.env.example
`)
	if got, _ := ig.Match(".env", false); !got {
		t.Error(".env should be ignored")
	}
	if got, _ := ig.Match(".env.example", false); got {
		t.Error(".env.example should be un-ignored by the negation")
	}
}

// Order is the whole semantic: the same two rules reversed mean the opposite.
func TestIgnore_OrderDecides(t *testing.T) {
	after := parse(t, "", "*.log\n!keep.log\n")
	if got, _ := after.Match("keep.log", false); got {
		t.Error("a negation after the broad rule should win")
	}

	before := parse(t, "", "!keep.log\n*.log\n")
	if got, _ := before.Match("keep.log", false); !got {
		t.Error("a negation before the broad rule should be overridden by it")
	}
}

func TestIgnore_UndecidedFallsThrough(t *testing.T) {
	ig := parse(t, "", "*.log\n")
	if _, decided := ig.Match("main.go", false); decided {
		t.Error("an unmatched path must leave the decision to an outer file")
	}
}

// A nested ignore file governs its own subtree and nothing above it.
func TestIgnore_NestedFileIsScopedToItsDirectory(t *testing.T) {
	ig := parse(t, "vendor", "*.go\n")

	if got, decided := ig.Match("vendor/lib/a.go", false); !decided || !got {
		t.Error("a path inside the subtree should be ignored")
	}
	if _, decided := ig.Match("cmd/main.go", false); decided {
		t.Error("a path outside the subtree is not this file's business")
	}
}

// Deeper files win, and a negation in one can un-ignore what the root ignored.
func TestStack_DeeperFileWins(t *testing.T) {
	st := Stack{
		parse(t, "", "*.go\n"),
		parse(t, "keep", "!*.go\n"),
	}

	if !st.Ignored("cmd/main.go", false) {
		t.Error("the root rule should still apply outside keep/")
	}
	if st.Ignored("keep/main.go", false) {
		t.Error("the nested negation should win inside keep/")
	}
}

func TestIgnore_CharacterClass(t *testing.T) {
	ig := parse(t, "", "*.[oa]\ntest_[!x]*.go\n")

	for _, c := range []struct {
		path string
		want bool
	}{
		{"main.o", true},
		{"lib.a", true},
		{"main.c", false},
		{"test_a1.go", true},
		{"test_x1.go", false},
	} {
		if got, _ := ig.Match(c.path, false); got != c.want {
			t.Errorf("Match(%q) = %v, want %v", c.path, got, c.want)
		}
	}
}

// A rule that does not compile is a rule its author believes is protecting
// them, so it fails loudly rather than being skipped.
func TestParseIgnore_RejectsAMalformedPattern(t *testing.T) {
	if _, err := ParseIgnore("test", "", strings.NewReader("[unterminated\n")); err == nil {
		t.Fatal("an unterminated character class was accepted")
	}
}

func TestParseIgnore_ReadsFingerprints(t *testing.T) {
	ig := parse(t, "", `
# a path rule and two fingerprints
testdata/
0123456789abcdef0123456789abcdef  # the CPF in the fixture
fedcba9876543210fedcba9876543210
`)

	reason, ok := ig.IgnoredFingerprint("0123456789abcdef0123456789abcdef")
	if !ok {
		t.Fatal("the fingerprint was not recorded")
	}
	if reason != "the CPF in the fixture" {
		t.Errorf("reason = %q", reason)
	}

	if reason, ok := ig.IgnoredFingerprint("fedcba9876543210fedcba9876543210"); !ok || reason != "" {
		t.Errorf("a fingerprint with no comment: reason = %q, ok = %v", reason, ok)
	}
	if _, ok := ig.IgnoredFingerprint("00000000000000000000000000000000"); ok {
		t.Error("an unlisted fingerprint was reported as ignored")
	}

	// A fingerprint line must not also become a path pattern.
	if got, _ := ig.Match("0123456789abcdef0123456789abcdef", false); got {
		t.Error("a fingerprint was compiled as a path pattern too")
	}
}

// Fingerprints are checked innermost first, so a nested file can explain a
// finding the root also silences.
func TestStack_FingerprintFromTheDeepestFile(t *testing.T) {
	fp := "0123456789abcdef0123456789abcdef"
	st := Stack{
		parse(t, "", fp+" # from the root\n"),
		parse(t, "sub", fp+" # from sub\n"),
	}
	if reason, _ := st.IgnoredFingerprint(fp); reason != "from sub" {
		t.Errorf("reason = %q, want the deepest file's", reason)
	}
}

func TestLoadIgnore_MissingFileIsNotAnError(t *testing.T) {
	ig, err := LoadIgnore(t.TempDir()+"/.gitignore", "")
	if err != nil {
		t.Fatalf("LoadIgnore: %v", err)
	}
	if ig != nil {
		t.Error("a missing file should yield a nil Ignore")
	}
	// A nil Ignore has to be usable, since that is the common case.
	if got, decided := ig.Match("anything", false); got || decided {
		t.Error("a nil Ignore decided something")
	}
}
