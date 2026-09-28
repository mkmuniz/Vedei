// Package scan walks a path and reports what the engines find in it.
//
// This is the reporting side of nadzor, so it fails closed (ADR-005): a file
// that could not be read is an error the caller hears about, because a scan
// that silently skipped half a tree and reported "clean" is worse than a red
// build.
package scan

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path"
	"regexp"
	"strings"
)

// Pattern is one gitignore-style rule.
type Pattern struct {
	// Raw is the line as written, kept for error messages and for --explain.
	Raw string
	// Negate is set for a "!" rule, which un-ignores a path an earlier rule
	// matched.
	Negate bool
	// DirOnly is set for a rule ending in "/", which matches directories only.
	DirOnly bool

	// re matches the path itself or anything under it. reSubtree matches only
	// something under it, which is what a "dir/" rule needs when the candidate
	// is a file: git never descends into an ignored directory, so every file
	// below it is ignored even though the rule is directory-only.
	re        *regexp.Regexp
	reSubtree *regexp.Regexp
}

// Ignore is the rule set from one ignore file, applied to paths relative to
// the directory holding it.
//
// It implements the subset of gitignore that appears in real files: comments,
// blank lines, negation, a trailing slash for directories, a leading or
// embedded slash for anchoring, "*", "?", "**" and character classes. It does
// not implement the parts nobody writes by hand, and says so rather than
// pretending: an escaped "#" or "!" outside a class, and a trailing backslash,
// are treated literally.
type Ignore struct {
	// Source is the file the rules came from, for error messages.
	Source string
	// Dir is the directory the rules apply to, relative to the scan root and
	// slash-separated. Empty means the root itself. A nested .gitignore only
	// governs its own subtree, so a path outside Dir is not its business.
	Dir      string
	Patterns []Pattern

	// Fingerprints are the finding fingerprints this file silences, from a
	// .nadzorignore. They are matched against detect.Finding.Fingerprint, not
	// against a path, so an entry survives the file being moved or renamed.
	Fingerprints map[string]string // fingerprint -> the reason on that line
}

// fingerprintLine matches a bare fingerprint, optionally followed by a reason
// comment: 32 hex characters, as fingerprint.Length says.
var fingerprintLine = regexp.MustCompile(`^([0-9a-f]{32})\s*(?:#\s*(.*))?$`)

// ParseIgnore reads ignore rules from r.
//
// source names the file for error messages. A malformed pattern is an error
// rather than a silent skip: a rule that does not compile is a rule the author
// believes is protecting them.
func ParseIgnore(source, dir string, r io.Reader) (*Ignore, error) {
	ig := &Ignore{Source: source, Dir: strings.Trim(path.Clean("/"+dir), "/")}

	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 4<<10), 1<<20)
	for line := 1; sc.Scan(); line++ {
		raw := sc.Text()
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		if m := fingerprintLine.FindStringSubmatch(trimmed); m != nil {
			if ig.Fingerprints == nil {
				ig.Fingerprints = map[string]string{}
			}
			ig.Fingerprints[m[1]] = strings.TrimSpace(m[2])
			continue
		}

		p, err := compilePattern(trimmed)
		if err != nil {
			return nil, fmt.Errorf("%s:%d: %w", source, line, err)
		}
		ig.Patterns = append(ig.Patterns, p)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("reading %s: %w", source, err)
	}
	return ig, nil
}

// LoadIgnore reads an ignore file, returning nil when it does not exist.
//
// A missing ignore file is the normal case, not an error; anything else about
// it is an error, because a file that exists and cannot be read may be
// silencing a finding the caller needs.
func LoadIgnore(filePath, dir string) (*Ignore, error) {
	f, err := os.Open(filePath) //nolint:gosec // the caller names the file
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("opening %s: %w", filePath, err)
	}
	defer func() { _ = f.Close() }()
	return ParseIgnore(filePath, dir, f)
}

// Match reports whether relPath matches, and whether any rule decided at all.
//
// The last matching rule wins, which is what makes negation work: a "!" rule
// after a broad one un-ignores the exception. A caller that sees decided=false
// must fall back to an outer ignore file.
func (ig *Ignore) Match(relPath string, isDir bool) (ignored, decided bool) {
	if ig == nil {
		return false, false
	}
	relPath = strings.TrimPrefix(path.Clean(relPath), "./")

	// Rules are relative to the file holding them, so a path outside that
	// subtree is out of scope and a path inside it is re-based.
	if ig.Dir != "" {
		prefix := ig.Dir + "/"
		if !strings.HasPrefix(relPath, prefix) {
			return false, false
		}
		relPath = relPath[len(prefix):]
	}

	for _, p := range ig.Patterns {
		re := p.re
		if p.DirOnly && !isDir {
			re = p.reSubtree
		}
		if re.MatchString(relPath) {
			ignored, decided = !p.Negate, true
		}
	}
	return ignored, decided
}

// IgnoredFingerprint returns the reason a finding is silenced, and whether it
// is. An empty reason with true means the entry carried no comment.
func (ig *Ignore) IgnoredFingerprint(fp string) (reason string, ok bool) {
	if ig == nil || ig.Fingerprints == nil {
		return "", false
	}
	reason, ok = ig.Fingerprints[fp]
	return reason, ok
}

// compilePattern turns one gitignore line into a regexp anchored the way git
// anchors it.
func compilePattern(line string) (Pattern, error) {
	p := Pattern{Raw: line}

	if strings.HasPrefix(line, "!") {
		p.Negate = true
		line = line[1:]
	}
	if strings.HasSuffix(line, "/") {
		p.DirOnly = true
		line = strings.TrimSuffix(line, "/")
	}
	if line == "" {
		return Pattern{}, fmt.Errorf("empty pattern")
	}

	// A slash anywhere but at the end anchors the pattern to the directory
	// holding the ignore file. Without one, the pattern matches at any depth.
	anchored := strings.Contains(line, "/")
	line = strings.TrimPrefix(line, "/")

	expr, err := globToRegexp(line)
	if err != nil {
		return Pattern{}, err
	}
	if !anchored {
		expr = `(?:.*/)?` + expr
	}
	// Matching the path itself also ignores everything under it, which is how
	// a directory rule silences a subtree.
	re, err := regexp.Compile(`^` + expr + `(?:/.*)?$`)
	if err != nil {
		return Pattern{}, fmt.Errorf("pattern %q: %w", p.Raw, err)
	}
	subtree, err := regexp.Compile(`^` + expr + `/.+$`)
	if err != nil {
		return Pattern{}, fmt.Errorf("pattern %q: %w", p.Raw, err)
	}
	p.re, p.reSubtree = re, subtree
	return p, nil
}

// globToRegexp translates a gitignore glob.
//
// The rule that matters: "*" and "?" never cross a "/", while "**" does. Get
// that wrong and "*.go" silences a whole tree.
func globToRegexp(glob string) (string, error) {
	var b strings.Builder
	b.Grow(len(glob) * 2)

	for i := 0; i < len(glob); i++ {
		switch c := glob[i]; c {
		case '*':
			if i+1 < len(glob) && glob[i+1] == '*' {
				i++
				switch {
				case i+1 < len(glob) && glob[i+1] == '/':
					// "**/" matches zero or more leading directories.
					i++
					b.WriteString(`(?:.*/)?`)
				case b.Len() > 0:
					// A trailing "**" matches the rest of the path.
					b.WriteString(`.*`)
				default:
					b.WriteString(`.*`)
				}
				continue
			}
			b.WriteString(`[^/]*`)
		case '?':
			b.WriteString(`[^/]`)
		case '[':
			class, next, err := charClass(glob, i)
			if err != nil {
				return "", err
			}
			b.WriteString(class)
			i = next
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	return b.String(), nil
}

// charClass copies a bracket expression through, translating git's "!"
// negation to the regexp "^" form.
func charClass(glob string, start int) (expr string, end int, err error) {
	i := start + 1
	var b strings.Builder
	b.WriteByte('[')
	if i < len(glob) && (glob[i] == '!' || glob[i] == '^') {
		b.WriteByte('^')
		i++
	}
	// A "]" immediately after the opening is a literal.
	if i < len(glob) && glob[i] == ']' {
		b.WriteString(`\]`)
		i++
	}
	for ; i < len(glob); i++ {
		if glob[i] == ']' {
			b.WriteByte(']')
			return b.String(), i, nil
		}
		if glob[i] == '\\' && i+1 < len(glob) {
			b.WriteString(regexp.QuoteMeta(string(glob[i+1])))
			i++
			continue
		}
		b.WriteByte(glob[i])
	}
	return "", 0, fmt.Errorf("unterminated character class in %q", glob[start:])
}

// Stack is the chain of ignore files in effect, outermost first.
//
// Deeper files win, matching git: a .gitignore in a subdirectory overrides the
// one above it, and a negation there can un-ignore what the root ignored.
type Stack []*Ignore

// Ignored reports whether a path relative to the stack's root is ignored.
func (s Stack) Ignored(relPath string, isDir bool) bool {
	ignored := false
	for _, ig := range s {
		if got, decided := ig.Match(relPath, isDir); decided {
			ignored = got
		}
	}
	return ignored
}

// IgnoredFingerprint returns the reason a finding is silenced by any file in
// the stack.
func (s Stack) IgnoredFingerprint(fp string) (reason string, ok bool) {
	for i := len(s) - 1; i >= 0; i-- {
		if reason, ok := s[i].IgnoredFingerprint(fp); ok {
			return reason, true
		}
	}
	return "", false
}
