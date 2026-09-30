package scan

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"

	"github.com/mkmuniz/vedei/detect"
)

// Defaults for a Scanner. They are values rather than hard limits so a caller
// scanning something unusual can raise them and say so.
const (
	// DefaultMaxFileSize skips a file larger than this. The engines hold the
	// whole file in memory, so an unbounded scan of a repository with a large
	// asset is a way to run out of it.
	DefaultMaxFileSize = 8 << 20

	// sniffLen is how much of a file is read to decide whether it is text. A
	// NUL byte in the first few KB is the same heuristic git uses.
	sniffLen = 8 << 10
)

// alwaysSkipped are directories that never hold anything worth reporting and
// are large enough that walking them is most of the runtime.
//
// This is a default, not a rule: --no-default-ignores turns it off, because a
// leaked credential committed into vendor/ is still leaked.
var alwaysSkipped = map[string]bool{
	".git": true, ".hg": true, ".svn": true,
	"node_modules": true, "vendor": true, ".venv": true, "venv": true,
	"__pycache__": true, ".mypy_cache": true, ".pytest_cache": true,
	"target": true, "dist": true, "build": true, ".next": true,
	".terraform": true, ".gradle": true, ".idea": true, ".cache": true,
}

// FileResult is what one file yielded.
//
// Path is relative to the scan root and slash-separated. That is not cosmetic:
// SARIF uploaded to GitHub is matched against the repository tree, so an
// absolute path lands the alert on no file at all. A caller that needs to open
// the file joins it back onto the root it passed.
type FileResult struct {
	Path     string
	Findings []detect.Finding
}

// Result is the outcome of a scan.
//
// Errs is not folded into a single error because a scan of a thousand files
// that hit one permission problem still has 999 useful answers. The caller
// reports them and fails, per ADR-005 — it does not report clean.
type Result struct {
	Files   []FileResult
	Scanned int
	Skipped int
	Bytes   int64
	Ignored int // findings silenced by a .vedeiignore fingerprint
	Errs    []error
}

// Findings flattens the per-file results, in walk order.
func (r Result) Findings() []detect.Finding {
	var out []detect.Finding
	for _, f := range r.Files {
		out = append(out, f.Findings...)
	}
	return out
}

// Total is how many findings the scan produced.
func (r Result) Total() int {
	n := 0
	for _, f := range r.Files {
		n += len(f.Findings)
	}
	return n
}

// Scanner walks a tree and runs an engine over every text file in it.
type Scanner struct {
	engine detect.Engine

	maxFileSize   int64
	workers       int
	useGitignore  bool
	useDefaults   bool
	followSymlink bool
}

// Option configures a Scanner.
type Option func(*Scanner)

// WithMaxFileSize sets the size above which a file is skipped. Zero means no
// limit, which is a choice the caller makes about its own memory.
func WithMaxFileSize(n int64) Option { return func(s *Scanner) { s.maxFileSize = n } }

// WithWorkers sets how many files are scanned in parallel.
func WithWorkers(n int) Option {
	return func(s *Scanner) {
		if n > 0 {
			s.workers = n
		}
	}
}

// WithGitignore controls whether .gitignore files are honoured.
func WithGitignore(on bool) Option { return func(s *Scanner) { s.useGitignore = on } }

// WithDefaultIgnores controls whether the built-in directory list is skipped.
// Turning it off is the honest choice for an audit: a credential committed into
// vendor/ is still committed.
func WithDefaultIgnores(on bool) Option { return func(s *Scanner) { s.useDefaults = on } }

// WithFollowSymlinks controls whether symlinks are followed.
//
// Off by default, and not only for speed: a link pointing outside the tree
// makes a scan report paths the caller did not ask about, and a cycle makes it
// never finish.
func WithFollowSymlinks(on bool) Option { return func(s *Scanner) { s.followSymlink = on } }

// NewScanner returns a Scanner over engine.
func NewScanner(engine detect.Engine, opts ...Option) *Scanner {
	s := &Scanner{
		engine:       engine,
		maxFileSize:  DefaultMaxFileSize,
		workers:      runtime.GOMAXPROCS(0),
		useGitignore: true,
		useDefaults:  true,
	}
	for _, o := range opts {
		o(s)
	}
	return s
}

// Scan walks root and reports what the engine found.
//
// A single file as root is scanned directly, because "vedei scan file.env" is
// what a person types first.
func (s *Scanner) Scan(ctx context.Context, root string) (Result, error) {
	info, err := os.Stat(root)
	if err != nil {
		return Result{}, fmt.Errorf("scan: %w", err)
	}

	if !info.IsDir() {
		// A single file keeps the name the caller typed: there is no root to be
		// relative to, and "." would be useless in a report.
		res := Result{}
		findings, n, err := s.scanFile(ctx, root, filepath.ToSlash(root), info.Size())
		if err != nil {
			return Result{}, err
		}
		res.Scanned, res.Bytes = 1, n
		if len(findings) > 0 {
			res.Files = append(res.Files, FileResult{Path: filepath.ToSlash(root), Findings: findings})
		}
		return res, nil
	}

	own, err := LoadIgnore(filepath.Join(root, ".vedeiignore"), "")
	if err != nil {
		return Result{}, err
	}

	paths, res, err := s.walk(ctx, root, own)
	if err != nil {
		return res, err
	}

	var ignores Stack
	if own != nil {
		ignores = Stack{own}
	}
	files, scanRes := s.scanAll(ctx, root, paths, ignores)
	res.Files = files
	res.Scanned = scanRes.Scanned
	res.Bytes = scanRes.Bytes
	res.Ignored = scanRes.Ignored
	res.Errs = append(res.Errs, scanRes.Errs...)
	return res, nil
}

// walk collects the paths to scan, applying ignore rules as it descends so an
// ignored directory is never entered.
// own is the .vedeiignore rule set, applied after the gitignore chain so it
// decides last: "!secret.env" there forces a scan of something git hides.
func (s *Scanner) walk(ctx context.Context, root string, own *Ignore) ([]string, Result, error) {
	var (
		paths []string
		res   Result
		stack Stack
	)

	ignored := func(rel string, isDir bool) bool {
		out := stack.Ignored(rel, isDir)
		if got, decided := own.Match(rel, isDir); decided {
			out = got
		}
		return out
	}

	if s.useGitignore {
		ig, err := LoadIgnore(filepath.Join(root, ".gitignore"), "")
		if err != nil {
			return nil, res, err
		}
		if ig != nil {
			stack = append(stack, ig)
		}
	}

	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		if err != nil {
			// A directory we cannot read is recorded and stepped over: the rest
			// of the tree still has answers, and the caller still fails.
			res.Errs = append(res.Errs, fmt.Errorf("scan: %w", err))
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}

		rel, relErr := filepath.Rel(root, p)
		if relErr != nil {
			res.Errs = append(res.Errs, fmt.Errorf("scan: %s: %w", p, relErr))
			return nil
		}
		rel = filepath.ToSlash(rel)
		if rel == "." {
			return nil
		}

		if d.IsDir() {
			if s.useDefaults && alwaysSkipped[d.Name()] {
				return fs.SkipDir
			}
			if ignored(rel, true) {
				return fs.SkipDir
			}
			if s.useGitignore {
				ig, err := LoadIgnore(filepath.Join(p, ".gitignore"), rel)
				if err != nil {
					return err
				}
				if ig != nil {
					stack = append(stack, ig)
				}
			}
			return nil
		}

		if d.Type()&fs.ModeSymlink != 0 && !s.followSymlink {
			res.Skipped++
			return nil
		}
		if !d.Type().IsRegular() && d.Type()&fs.ModeSymlink == 0 {
			// A device, socket or pipe. Reading one can block forever.
			res.Skipped++
			return nil
		}
		if ignored(rel, false) {
			res.Skipped++
			return nil
		}
		paths = append(paths, p)
		return nil
	})
	if err != nil {
		return nil, res, fmt.Errorf("scan: walking %s: %w", root, err)
	}

	// Walk order is already sorted per directory; sorting the whole set makes
	// the report stable across platforms.
	sort.Strings(paths)
	return paths, res, nil
}

// scanAll runs the engine over paths, in parallel, and returns results in
// walk order regardless of which worker finished first.
func (s *Scanner) scanAll(ctx context.Context, root string, paths []string, ignores Stack) ([]FileResult, Result) {
	type outcome struct {
		i       int
		res     FileResult
		bytes   int64
		ignored int
		err     error
	}

	jobs := make(chan int)
	results := make(chan outcome, s.workers)

	var wg sync.WaitGroup
	for range s.workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				p := paths[i]
				rel := Rel(root, p)
				findings, n, err := s.scanFile(ctx, p, rel, -1)
				o := outcome{i: i, bytes: n, err: err}
				if err == nil {
					kept, silenced := filterIgnored(findings, ignores)
					o.ignored = silenced
					if len(kept) > 0 {
						o.res = FileResult{Path: rel, Findings: kept}
					}
				}
				results <- o
			}
		}()
	}

	go func() {
		defer close(jobs)
		for i := range paths {
			select {
			case <-ctx.Done():
				return
			case jobs <- i:
			}
		}
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	ordered := make([]FileResult, len(paths))
	var res Result
	for o := range results {
		if o.err != nil {
			res.Errs = append(res.Errs, o.err)
			continue
		}
		res.Scanned++
		res.Bytes += o.bytes
		res.Ignored += o.ignored
		ordered[o.i] = o.res
	}

	out := make([]FileResult, 0, len(paths))
	for _, r := range ordered {
		if r.Path != "" {
			out = append(out, r)
		}
	}
	return out, res
}

// filterIgnored drops findings silenced by a fingerprint entry.
func filterIgnored(findings []detect.Finding, ignores Stack) (kept []detect.Finding, silenced int) {
	if len(ignores) == 0 {
		return findings, 0
	}
	for _, f := range findings {
		if _, ok := ignores.IgnoredFingerprint(f.Fingerprint); ok {
			silenced++
			continue
		}
		kept = append(kept, f)
	}
	return kept, silenced
}

// scanFile reads one file and runs the engine over it.
//
// p is the path on disk; reported is the name that goes into the report, which
// is relative to the scan root. size may be -1 when unknown, in which case it
// is stat'd here. Findings come back with the reported name on every location,
// because a report that names a type without a file is not actionable.
func (s *Scanner) scanFile(ctx context.Context, p, reported string, size int64) ([]detect.Finding, int64, error) {
	if size < 0 {
		info, err := os.Stat(p)
		if err != nil {
			return nil, 0, fmt.Errorf("scan: %w", err)
		}
		size = info.Size()
	}
	if s.maxFileSize > 0 && size > s.maxFileSize {
		return nil, 0, nil
	}

	content, err := os.ReadFile(p) //#nosec G304 -- a file inside the tree the caller asked to scan; symlinks are skipped unless --follow-symlinks says otherwise
	if err != nil {
		return nil, 0, fmt.Errorf("scan: %w", err)
	}
	if isBinary(content) {
		return nil, 0, nil
	}

	findings, err := s.engine.Scan(ctx, content, detect.Metadata{Path: reported, Source: "file"})
	if err != nil {
		return nil, int64(len(content)), fmt.Errorf("scan: %s: %w", reported, err)
	}
	for i := range findings {
		for j := range findings[i].Locations {
			findings[i].Locations[j].Path = reported
		}
	}
	return findings, int64(len(content)), nil
}

// isBinary reports whether content looks like a binary file.
//
// A NUL byte in the first few KB is what git uses, and it is the right call
// here for a different reason: a regex over a compiled binary produces matches
// that pass a check digit and mean nothing.
func isBinary(content []byte) bool {
	head := content
	if len(head) > sniffLen {
		head = head[:sniffLen]
	}
	return bytes.IndexByte(head, 0) >= 0
}

// Reader scans anything readable, for callers with no file on disk — a git
// blob, a pipe, an HTTP body.
func (s *Scanner) Reader(ctx context.Context, r io.Reader, meta detect.Metadata) ([]detect.Finding, error) {
	limited := io.Reader(r)
	if s.maxFileSize > 0 {
		limited = io.LimitReader(r, s.maxFileSize+1)
	}
	content, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("scan: reading %s: %w", meta.Path, err)
	}
	if s.maxFileSize > 0 && int64(len(content)) > s.maxFileSize {
		return nil, nil
	}
	if isBinary(content) {
		return nil, nil
	}

	findings, err := s.engine.Scan(ctx, content, meta)
	if err != nil {
		return nil, fmt.Errorf("scan: %s: %w", meta.Path, err)
	}
	if meta.Path != "" {
		for i := range findings {
			for j := range findings[i].Locations {
				findings[i].Locations[j].Path = meta.Path
			}
		}
	}
	return findings, nil
}

// Rel makes p relative to root for display, falling back to p itself.
func Rel(root, p string) string {
	rel, err := filepath.Rel(root, p)
	if err != nil {
		return p
	}
	return strings.TrimPrefix(filepath.ToSlash(rel), "./")
}
