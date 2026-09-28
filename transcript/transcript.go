package transcript

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/mkmuniz/nadzor/detect"
)

// Agent names a coding agent whose session logs nadzor knows how to read.
type Agent string

// The agents supported so far.
const (
	AgentClaudeCode Agent = "claude-code"
	AgentCodex      Agent = "codex"
)

// Session is one transcript file and what was found in it.
type Session struct {
	Agent    Agent
	Path     string
	Modified time.Time
	Size     int64
	// Lines is how many records the file held.
	Lines int
	// Findings are the sensitive values that reached this transcript.
	// Their locations carry the line number within the file.
	Findings []detect.Finding
}

// Report is the result of auditing a set of transcripts.
type Report struct {
	Sessions []Session
	// Scanned and Skipped count files, not findings.
	Scanned int
	Skipped int
	// Errs holds per-file failures. Auditing continues past them: one
	// unreadable transcript must not hide what the others contain.
	Errs []error
}

// TotalFindings counts every finding across every session.
func (r Report) TotalFindings() int {
	n := 0
	for _, s := range r.Sessions {
		n += len(s.Findings)
	}
	return n
}

// DefaultRoots returns the directories where the supported agents keep their
// session logs, for those that exist on this machine.
//
// These files are plaintext with no encryption, no rotation and no expiry,
// and no security tool watches them. A .env has file permissions and a
// gitignore; a transcript has neither, while aggregating secrets from every
// source the agent ever touched.
func DefaultRoots() map[Agent]string {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	candidates := map[Agent]string{
		AgentClaudeCode: filepath.Join(home, ".claude", "projects"),
		AgentCodex:      filepath.Join(home, ".codex", "sessions"),
	}
	found := make(map[Agent]string, len(candidates))
	for a, dir := range candidates {
		if fi, err := os.Stat(dir); err == nil && fi.IsDir() {
			found[a] = dir
		}
	}
	return found
}

// Scanner audits transcripts for sensitive data that already reached them.
type Scanner struct {
	engine detect.Engine
	// maxFileSize skips a transcript larger than this. Auditing is not the
	// hot path, but a multi-gigabyte log should not exhaust memory either.
	maxFileSize int64
}

// NewScanner returns a Scanner over engine.
func NewScanner(engine detect.Engine) *Scanner {
	return &Scanner{engine: engine, maxFileSize: 512 << 20}
}

// ScanDir audits every .jsonl transcript under dir.
//
// A missing directory is an error, not an empty result: a caller who asked
// for a path and got "nothing found" would read that as clean.
func (s *Scanner) ScanDir(ctx context.Context, agent Agent, dir string) (Report, error) {
	var rep Report

	if fi, err := os.Stat(dir); err != nil {
		return rep, fmt.Errorf("transcript: %w", err)
	} else if !fi.IsDir() {
		return rep, fmt.Errorf("transcript: %s is not a directory", dir)
	}

	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			rep.Errs = append(rep.Errs, err)
			return nil
		}
		if d.IsDir() || !strings.HasSuffix(path, ".jsonl") {
			return nil
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}

		info, err := d.Info()
		if err != nil {
			rep.Errs = append(rep.Errs, err)
			return nil
		}
		if info.Size() > s.maxFileSize {
			rep.Skipped++
			rep.Errs = append(rep.Errs, fmt.Errorf("%s: %d bytes exceeds the size cap", path, info.Size()))
			return nil
		}

		sess, err := s.ScanFile(ctx, agent, path)
		if err != nil {
			rep.Errs = append(rep.Errs, err)
			return nil
		}
		rep.Scanned++
		if len(sess.Findings) > 0 {
			rep.Sessions = append(rep.Sessions, sess)
		}
		return nil
	})
	if err != nil {
		return rep, err
	}

	// Most recently touched first: that is what someone auditing wants to
	// see, and what is most likely still reachable by an attacker.
	sort.Slice(rep.Sessions, func(i, j int) bool {
		return rep.Sessions[i].Modified.After(rep.Sessions[j].Modified)
	})
	return rep, nil
}

// ScanFile audits one transcript.
func (s *Scanner) ScanFile(ctx context.Context, agent Agent, path string) (Session, error) {
	f, err := os.Open(path) //#nosec G304 -- read-only, on a transcript the caller named or that DefaultRoots found in their own home
	if err != nil {
		return Session{}, fmt.Errorf("opening %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	info, err := f.Stat()
	if err != nil {
		return Session{}, fmt.Errorf("stat %s: %w", path, err)
	}

	sess := Session{Agent: agent, Path: path, Modified: info.ModTime(), Size: info.Size()}
	byPrint := map[string]int{}

	sc := bufio.NewScanner(f)
	// A single record can be large: a transcript holds whole file contents.
	sc.Buffer(make([]byte, 0, 64<<10), 16<<20)

	for line := 1; sc.Scan(); line++ {
		if err := ctx.Err(); err != nil {
			return sess, err
		}
		sess.Lines++

		text := readableText(sc.Bytes())
		if text == "" {
			continue
		}

		found, err := s.engine.Scan(ctx, []byte(text), detect.Metadata{
			Path:   path,
			Source: "transcript",
			Extra:  map[string]string{"agent": string(agent)},
		})
		if err != nil {
			return sess, fmt.Errorf("scanning %s line %d: %w", path, line, err)
		}

		for _, fd := range found {
			if i, seen := byPrint[fd.Fingerprint]; seen {
				sess.Findings[i].Locations = append(sess.Findings[i].Locations,
					detect.Location{Path: path, Line: line})
				continue
			}
			fd.Locations = []detect.Location{{Path: path, Line: line}}
			byPrint[fd.Fingerprint] = len(sess.Findings)
			sess.Findings = append(sess.Findings, fd)
		}
	}
	if err := sc.Err(); err != nil && !errors.Is(err, io.EOF) {
		return sess, fmt.Errorf("reading %s: %w", path, err)
	}
	return sess, nil
}

// readableText pulls the human-readable content out of one record.
//
// A transcript record is JSON with the text buried at varying depths, and
// the shape differs between agents and between versions. Rather than model
// every schema — which would silently miss a field when one changes — this
// walks the decoded value and concatenates every string it finds. Scanning
// more than necessary is the safe direction: the cost is a little time, and
// the alternative is missing the field where the secret actually sits.
func readableText(line []byte) string {
	var v any
	if err := json.Unmarshal(line, &v); err != nil {
		// Not valid JSON: scan the raw line rather than skipping it.
		return string(line)
	}
	var b strings.Builder
	collectStrings(v, &b, 0)
	return b.String()
}

// maxDepth bounds recursion so a deeply nested record cannot exhaust the
// stack. Transcript records are a few levels deep in practice.
const maxDepth = 64

func collectStrings(v any, b *strings.Builder, depth int) {
	if depth > maxDepth {
		return
	}
	switch t := v.(type) {
	case string:
		b.WriteString(t)
		b.WriteByte('\n')
	case []any:
		for _, e := range t {
			collectStrings(e, b, depth+1)
		}
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys) // deterministic output
		for _, k := range keys {
			collectStrings(t[k], b, depth+1)
		}
	}
}
