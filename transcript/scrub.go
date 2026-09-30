package transcript

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/mkmuniz/vedei/detect"
	"github.com/mkmuniz/vedei/stream"
)

// maxScrubDepth bounds the recursion that rewrites a record. A transcript is
// data from outside, and a deeply nested document is a cheap way to exhaust a
// stack.
const maxScrubDepth = 64

// ScrubOptions controls a scrub.
type ScrubOptions struct {
	// DryRun reports what would change and writes nothing. The CLI requires it
	// first, because the alternative is discovering the tool's behaviour on your
	// own session history.
	DryRun bool

	// NoBackup skips the backup copy. It exists because someone will want it,
	// not because it is a good idea.
	NoBackup bool

	// Annotate wraps each replacement in a marker, so a person reading the
	// transcript later knows why a value looks like that. Off means a bare mask.
	Annotate bool
}

// ScrubResult is what one scrub did, or would do.
type ScrubResult struct {
	Path   string
	Backup string
	DryRun bool

	// Lines is the record count, and LinesChanged how many were rewritten.
	Lines        int
	LinesChanged int
	// Replacements counts individual values replaced, which is higher than
	// LinesChanged when a record held several.
	Replacements int
	// Findings is what was removed. Values are redacted, as everywhere.
	Findings []detect.Finding
}

// Scrub rewrites a transcript with every detected value masked.
//
// This is the only command in vedei that modifies a file the user did not hand
// it, and the only one where a bug destroys something irreplaceable. The order
// below is the safety argument, and each step exists because skipping it is how
// this goes wrong:
//
//  1. Scan first. Nothing is touched if there is nothing to remove.
//  2. Copy to a backup and verify it by hash, not by length.
//  3. Write a new file beside the original, fsync it, then rename. A rename
//     within a directory is atomic, so a crash leaves either the old file or
//     the new one, never half of either.
//  4. Re-read the result and refuse to keep it unless every record still parses
//     and the record count is unchanged.
//
// It does not try to detect an agent appending to the file at the same time,
// because it cannot. Close the session first.
func (s *Scanner) Scrub(ctx context.Context, agent Agent, path string, opts ScrubOptions) (ScrubResult, error) {
	redact, err := s.redactor(ctx, opts.Annotate)
	if err != nil {
		return ScrubResult{}, err
	}

	// Pass one writes nowhere. It answers whether anything needs to change, so
	// a clean transcript is never rewritten, never backed up, and keeps its
	// modification time.
	res, err := s.rewrite(ctx, agent, path, io.Discard, redact)
	if err != nil {
		return res, err
	}
	res.DryRun = opts.DryRun
	if res.Replacements == 0 || opts.DryRun {
		return res, nil
	}

	// Lstat, not Stat, and a regular-file check.
	//
	// The rename at the end replaces whatever sits at this path. Pointed at a
	// symlink, Stat would report the target's mode, the rename would destroy
	// the link, and the value the command reported as removed would still be
	// in the target — the tool claiming a leak was closed when it was not.
	// gosec flagged the open as path-traversal-shaped; this is what was behind
	// it.
	info, err := os.Lstat(path)
	if err != nil {
		return res, fmt.Errorf("stat %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return res, fmt.Errorf("%s is not a regular file (%s); "+
			"scrub rewrites in place and will not follow it", path, info.Mode().Type())
	}

	if !opts.NoBackup {
		backup, err := backupFile(path, info.Mode())
		if err != nil {
			return res, err
		}
		res.Backup = backup
	}

	tmp, err := os.CreateTemp(filepath.Dir(path), ".vedei-scrub-*")
	if err != nil {
		return res, fmt.Errorf("creating a temporary file beside %s: %w", path, err)
	}
	tmpName := tmp.Name()
	// Every failure from here removes the temporary file rather than leaving
	// litter in the user's transcript directory.
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}()

	buf := bufio.NewWriter(tmp)
	if _, err := s.rewrite(ctx, agent, path, buf, redact); err != nil {
		return res, err
	}
	if err := buf.Flush(); err != nil {
		return res, fmt.Errorf("writing %s: %w", tmpName, err)
	}
	// fsync before the rename: without it a crash can leave the directory entry
	// pointing at a file whose contents never reached the disk.
	if err := tmp.Sync(); err != nil {
		return res, fmt.Errorf("syncing %s: %w", tmpName, err)
	}
	if err := tmp.Chmod(info.Mode()); err != nil {
		return res, fmt.Errorf("setting the mode on %s: %w", tmpName, err)
	}
	if err := tmp.Close(); err != nil {
		return res, fmt.Errorf("closing %s: %w", tmpName, err)
	}

	if err := verifyScrubbed(tmpName, res.Lines); err != nil {
		return res, err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return res, fmt.Errorf("replacing %s: %w", path, err)
	}
	return res, nil
}

// redactor rewrites one string, returning the result and what was found in it.
//
// It scans each string rather than substituting the values a first pass
// reported, and that is not an optimization detail — it is a correctness one.
// Findings are deduplicated by a fingerprint that normalizes punctuation, so one
// finding's Raw holds a single spelling. A transcript that mentions a CPF as
// "529.982.247-25" and again as "52998224725" produces one finding, and
// substituting its Raw leaves the other spelling in the file. Scanning per
// string and replacing by byte offset has no such gap.
type redactor func(s string) (out string, findings []detect.Finding, changed bool)

func (s *Scanner) redactor(ctx context.Context, annotate bool) (redactor, error) {
	opts := []stream.Option{}
	if !annotate {
		opts = append(opts, stream.WithAnnotator(func(f detect.Finding) string { return f.Redacted }))
	}
	proc, err := stream.New(s.engine, opts...)
	if err != nil {
		return nil, fmt.Errorf("scrub: %w", err)
	}

	return func(in string) (string, []detect.Finding, bool) {
		// A string too short to hold the shortest document cannot match, and a
		// transcript is mostly such strings — keys, roles, uuids, short words.
		if len(in) < minScannable {
			return in, nil, false
		}
		out, res := proc.Process(ctx, in, detect.Metadata{Source: "transcript"})
		if res.Degraded || !res.Redacted {
			return in, nil, false
		}
		return out, res.Findings, true
	}, nil
}

// minScannable is the length of the shortest thing the Brazilian engine can
// match, so anything shorter is skipped without calling the engine.
const minScannable = 11

// rewrite streams path through w, replacing values inside each record, and
// reports what it did. Passing io.Discard makes it an analysis pass.
func (s *Scanner) rewrite(ctx context.Context, agent Agent, path string, w io.Writer,
	redact redactor,
) (ScrubResult, error) {
	res := ScrubResult{Path: path}

	f, err := os.Open(path) //#nosec G304 -- read-only, on the transcript the caller named
	if err != nil {
		return res, fmt.Errorf("opening %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), 16<<20)

	// One value in several records is one finding with several locations, the
	// same shape ScanFile reports.
	byPrint := map[string]int{}

	for line := 1; sc.Scan(); line++ {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		res.Lines++

		out, found, err := scrubRecord(sc.Bytes(), redact)
		if err != nil {
			return res, fmt.Errorf("%s line %d: %w", path, line, err)
		}
		if len(found) > 0 {
			res.LinesChanged++
			res.Replacements += len(found)
			for _, fd := range found {
				if i, seen := byPrint[fd.Fingerprint]; seen {
					res.Findings[i].Locations = append(res.Findings[i].Locations,
						detect.Location{Path: path, Line: line})
					continue
				}
				fd.Locations = []detect.Location{{Path: path, Line: line}}
				fd.Extra = withAgent(fd.Extra, agent)
				byPrint[fd.Fingerprint] = len(res.Findings)
				res.Findings = append(res.Findings, fd)
			}
		}
		if _, err := w.Write(append(out, '\n')); err != nil {
			return res, fmt.Errorf("writing a record: %w", err)
		}
	}
	if err := sc.Err(); err != nil {
		return res, fmt.Errorf("reading %s: %w", path, err)
	}
	return res, nil
}

// withAgent records which agent's transcript a finding came from, without
// mutating a map the engine may reuse.
func withAgent(extra map[string]string, agent Agent) map[string]string {
	out := make(map[string]string, len(extra)+1)
	for k, v := range extra {
		out[k] = v
	}
	out["agent"] = string(agent)
	return out
}

// scrubRecord rewrites one record, replacing values inside its strings.
//
// It walks the JSON token by token and re-emits it, rather than decoding into a
// map and marshalling that back. The difference matters: a map loses the order
// of the keys, and a plain decode turns every number into a float64, which
// silently rewrites a millisecond timestamp into scientific notation. Walking
// tokens keeps both.
//
// A record that is not valid JSON is replaced as plain text: a transcript that
// already held a malformed line keeps it, malformed, rather than being dropped.
func scrubRecord(line []byte, redact redactor) ([]byte, []detect.Finding, error) {
	if len(bytes.TrimSpace(line)) == 0 {
		return line, nil, nil
	}

	// The whole line has to be valid JSON before the token walk starts.
	//
	// Checking afterwards is not equivalent, and a fuzzer proved it: "0}" made
	// the decoder read 0 as a complete value and report nothing further, so the
	// record was rewritten as "0" and the brace was dropped. Silently
	// truncating a record is the worst thing this function can do, since the
	// original is then gone. json.Valid answers the question the walk assumes.
	if !json.Valid(line) {
		// A record that was not JSON keeps its values replaced as plain text,
		// and stays malformed rather than being dropped.
		replaced, plainFound, _ := redact(string(line))
		return []byte(replaced), plainFound, nil
	}

	dec := json.NewDecoder(bytes.NewReader(line))
	dec.UseNumber()

	var out bytes.Buffer
	out.Grow(len(line) + 64)

	found, err := emitValue(dec, &out, redact, 0)
	if err != nil {
		// json.Valid said yes, so this is the depth bound, not a parse error.
		// Leaving the record untouched is right: it is better to carry a value
		// vedei could not reach than to write a record it could not rebuild.
		return line, nil, fmt.Errorf("rewriting a record: %w", err)
	}
	return out.Bytes(), found, nil
}

// emitValue copies one JSON value from dec to out, rewriting strings.
func emitValue(dec *json.Decoder, out *bytes.Buffer, redact redactor, depth int) ([]detect.Finding, error) {
	if depth > maxScrubDepth {
		return nil, fmt.Errorf("record nested deeper than %d levels", maxScrubDepth)
	}

	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}

	switch v := tok.(type) {
	case json.Delim:
		switch v {
		case '{':
			return emitObject(dec, out, redact, depth)
		case '[':
			return emitArray(dec, out, redact, depth)
		default:
			return nil, fmt.Errorf("unexpected %q", v)
		}
	case string:
		replaced, found, _ := redact(v)
		if err := writeJSONString(out, replaced); err != nil {
			return nil, err
		}
		return found, nil
	case json.Number:
		out.WriteString(v.String())
		return nil, nil
	case bool:
		if v {
			out.WriteString("true")
		} else {
			out.WriteString("false")
		}
		return nil, nil
	case nil:
		out.WriteString("null")
		return nil, nil
	default:
		return nil, fmt.Errorf("unexpected token %T", tok)
	}
}

func emitObject(dec *json.Decoder, out *bytes.Buffer, redact redactor, depth int) ([]detect.Finding, error) {
	out.WriteByte('{')
	var all []detect.Finding
	first := true
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, ok := keyTok.(string)
		if !ok {
			return nil, fmt.Errorf("object key is %T, not a string", keyTok)
		}
		if !first {
			out.WriteByte(',')
		}
		first = false

		// Keys are not rewritten. A secret used as a JSON key would be strange,
		// and rewriting one changes the record's shape rather than its content.
		if err := writeJSONString(out, key); err != nil {
			return nil, err
		}
		out.WriteByte(':')

		found, err := emitValue(dec, out, redact, depth+1)
		if err != nil {
			return nil, err
		}
		all = append(all, found...)
	}
	if _, err := dec.Token(); err != nil { // the closing brace
		return nil, err
	}
	out.WriteByte('}')
	return all, nil
}

func emitArray(dec *json.Decoder, out *bytes.Buffer, redact redactor, depth int) ([]detect.Finding, error) {
	out.WriteByte('[')
	var all []detect.Finding
	first := true
	for dec.More() {
		if !first {
			out.WriteByte(',')
		}
		first = false
		found, err := emitValue(dec, out, redact, depth+1)
		if err != nil {
			return nil, err
		}
		all = append(all, found...)
	}
	if _, err := dec.Token(); err != nil { // the closing bracket
		return nil, err
	}
	out.WriteByte(']')
	return all, nil
}

// writeJSONString appends s as a JSON string with HTML escaping off, so a "<"
// in a record does not come back as < and change bytes nobody asked about.
func writeJSONString(out *bytes.Buffer, s string) error {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(s); err != nil {
		return fmt.Errorf("encoding a string: %w", err)
	}
	out.Write(bytes.TrimRight(b.Bytes(), "\n"))
	return nil
}

// backupFile copies path beside itself and verifies the copy by hash.
//
// By hash and not by length: a truncated copy of the right size is exactly the
// failure a backup is supposed to rule out.
func backupFile(path string, mode os.FileMode) (string, error) {
	name := fmt.Sprintf("%s.vedei-backup-%s", path, time.Now().UTC().Format("20060102T150405Z"))

	src, err := os.Open(path) //#nosec G304 -- read-only, the file about to be rewritten; Scrub has already refused anything but a regular file
	if err != nil {
		return "", fmt.Errorf("opening %s: %w", path, err)
	}
	defer func() { _ = src.Close() }()

	dst, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode) //#nosec G304 -- name is the transcript's own path plus a timestamp, and O_EXCL refuses to follow or overwrite anything already there
	if err != nil {
		return "", fmt.Errorf("creating %s: %w", name, err)
	}

	srcHash := sha256.New()
	if _, err := io.Copy(dst, io.TeeReader(src, srcHash)); err != nil {
		_ = dst.Close()
		_ = os.Remove(name)
		return "", fmt.Errorf("writing %s: %w", name, err)
	}
	if err := dst.Sync(); err != nil {
		_ = dst.Close()
		_ = os.Remove(name)
		return "", fmt.Errorf("syncing %s: %w", name, err)
	}
	if err := dst.Close(); err != nil {
		_ = os.Remove(name)
		return "", fmt.Errorf("closing %s: %w", name, err)
	}

	got, err := hashFile(name)
	if err != nil {
		_ = os.Remove(name)
		return "", err
	}
	if want := hex.EncodeToString(srcHash.Sum(nil)); got != want {
		_ = os.Remove(name)
		return "", fmt.Errorf("the backup of %s does not match the original", path)
	}
	return name, nil
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path) //#nosec G304 -- a path this package created moments ago
	if err != nil {
		return "", fmt.Errorf("opening %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("reading %s: %w", path, err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// verifyScrubbed refuses a rewritten file that is not a valid transcript.
//
// The record count has to match and every record that was JSON has to still be
// JSON. This runs before the rename, so a failure here leaves the original
// untouched — the whole point of writing beside it rather than in place.
func verifyScrubbed(path string, wantLines int) error {
	f, err := os.Open(path) //#nosec G304 -- a path this package created moments ago
	if err != nil {
		return fmt.Errorf("opening the rewritten file: %w", err)
	}
	defer func() { _ = f.Close() }()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), 16<<20)

	lines := 0
	for sc.Scan() {
		lines++
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 || line[0] != '{' && line[0] != '[' {
			continue // a record that was not JSON before is not JSON now
		}
		if !json.Valid(line) {
			return fmt.Errorf("the rewrite produced invalid JSON on record %d; the original was left alone", lines)
		}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("reading the rewritten file: %w", err)
	}
	if lines != wantLines {
		return fmt.Errorf("the rewrite produced %d record(s) where the original had %d; "+
			"the original was left alone", lines, wantLines)
	}
	return nil
}
