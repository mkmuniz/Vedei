package scan

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	"github.com/mkmuniz/vedei/detect"
)

// GitRef names a blob inside a repository, for a report a person can act on:
// "a1b2c3d:config.yml" is enough to run "git show" on.
type GitRef struct {
	Commit string
	Path   string
}

func (r GitRef) String() string {
	if r.Commit == "" {
		return r.Path
	}
	return r.Commit[:min(len(r.Commit), 12)] + ":" + r.Path
}

// GitScanner scans a repository's history and its pending changes.
//
// It drives the git binary rather than linking a git library. That is a real
// trade: it needs git on PATH, and it costs a process per invocation. What it
// buys is that pathological repositories, partial clones, worktrees, LFS and
// submodules behave exactly as the user's own git does, rather than as a
// reimplementation guesses. A secret scanner that disagrees with git about what
// is in a commit is worse than one that shells out.
type GitScanner struct {
	scanner *Scanner
	repo    string
	git     string
}

// NewGitScanner returns a scanner over the repository at repo.
func NewGitScanner(s *Scanner, repo string) (*GitScanner, error) {
	git, err := exec.LookPath("git")
	if err != nil {
		return nil, fmt.Errorf("scan: git is required for this command: %w", err)
	}
	return &GitScanner{scanner: s, repo: repo, git: git}, nil
}

// ErrRevisionLooksLikeAFlag is returned for a revision starting with "-".
var ErrRevisionLooksLikeAFlag = errors.New("scan: a revision may not start with '-'")

// checkRev refuses a revision git would read as an option.
//
// Arguments are passed as an array, so there is no shell to inject into, but
// git parses a leading "-" as a flag wherever a revision is expected. gosec
// flagged the exec call and the concern turned out to be real:
//
//	vedei diff --base "--output=/tmp/pwned"
//
// became "git diff --name-only -z --output=/tmp/pwned HEAD", and git wrote the
// file. A revision is never spelled with a leading dash, so refusing one costs
// nothing and closes the whole class rather than the one flag that was tried.
func checkRev(rev string) error {
	if strings.HasPrefix(rev, "-") {
		return fmt.Errorf("%w: %q", ErrRevisionLooksLikeAFlag, rev)
	}
	return nil
}

// run executes a git command in the repository and returns its stdout.
func (g *GitScanner) run(ctx context.Context, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, g.git, append([]string{"-C", g.repo}, args...)...) //#nosec G204 -- git from PATH with a fixed argument array and no shell; revisions are checked by checkRev, since git reads a leading dash as a flag
	var out, errBuf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errBuf
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(errBuf.String())
		if msg == "" {
			msg = err.Error()
		}
		return nil, fmt.Errorf("scan: git %s: %s", strings.Join(args, " "), msg)
	}
	return out.Bytes(), nil
}

// Staged scans what is about to be committed.
//
// This is what a pre-commit hook runs, so it looks at the index rather than the
// working tree: a file with a secret that was edited but not staged is not what
// this commit is about, and blocking on it would be wrong.
func (g *GitScanner) Staged(ctx context.Context) (Result, error) {
	names, err := g.run(ctx, "diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z")
	if err != nil {
		return Result{}, err
	}
	return g.scanIndexPaths(ctx, splitNUL(names))
}

// Diff scans the files that changed between two revisions.
//
// A range rather than the whole history is what CI wants: re-scanning every
// commit on every push is how a secret scanner becomes the slowest step in the
// pipeline, and the commits before the base were already scanned once.
func (g *GitScanner) Diff(ctx context.Context, base, head string) (Result, error) {
	for _, rev := range []string{base, head} {
		if err := checkRev(rev); err != nil {
			return Result{}, err
		}
	}

	names, err := g.run(ctx, "diff", "--name-only", "--diff-filter=ACMR", "-z", base, head)
	if err != nil {
		return Result{}, err
	}

	var res Result
	ignores, err := g.loadIgnore(ctx)
	if err != nil {
		return Result{}, err
	}

	for _, path := range splitNUL(names) {
		ref := GitRef{Commit: head, Path: path}
		// "rev:path" never begins with a dash here because head was checked,
		// and git resolves the whole string as one object name.
		blob, err := g.run(ctx, "show", head+":"+path)
		if err != nil {
			// A path deleted in head, or a submodule. Neither is a failure.
			continue
		}
		g.appendFindings(ctx, &res, ref, blob, ignores)
	}
	return res, nil
}

// History scans every blob reachable from the given revisions.
//
// This is the expensive one, and the only one that finds a credential that was
// committed and then removed — which is the common case, because removing it
// from the working tree is what people do instead of rotating it.
func (g *GitScanner) History(ctx context.Context, revs ...string) (Result, error) {
	if len(revs) == 0 {
		revs = []string{"--all"}
	} else {
		for _, rev := range revs {
			if err := checkRev(rev); err != nil {
				return Result{}, err
			}
		}
	}

	ignores, err := g.loadIgnore(ctx)
	if err != nil {
		return Result{}, err
	}

	commits, err := g.run(ctx, append([]string{"rev-list"}, revs...)...)
	if err != nil {
		return Result{}, err
	}

	var res Result
	// One blob may be reachable from many commits; scanning it once is the
	// difference between minutes and hours on a real repository.
	seen := map[string]bool{}

	for _, commit := range strings.Fields(string(commits)) {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		g.scanCommit(ctx, &res, commit, ignores, seen)
	}
	return res, nil
}

// scanCommit scans the blobs in one commit that have not been scanned yet.
func (g *GitScanner) scanCommit(ctx context.Context, res *Result, commit string, ignores Stack, seen map[string]bool) {
	entries, err := g.run(ctx, "ls-tree", "-r", "-z", "--long", commit)
	if err != nil {
		res.Errs = append(res.Errs, err)
		return
	}
	for _, e := range splitNUL(entries) {
		blob, path, size, ok := parseLsTree(e)
		if !ok || seen[blob] {
			continue
		}
		// An ignored path must not consume the blob. Identical content is
		// scanned once, so if the ignored copy marked it as seen, the same
		// bytes committed somewhere that is not ignored would never be
		// scanned — a leak hidden by whichever path sorted first.
		if ignores.Ignored(path, false) {
			continue
		}
		seen[blob] = true
		if g.scanner.maxFileSize > 0 && size > g.scanner.maxFileSize {
			res.Skipped++
			continue
		}

		content, err := g.run(ctx, "cat-file", "blob", blob)
		if err != nil {
			res.Errs = append(res.Errs, err)
			continue
		}
		g.appendFindings(ctx, res, GitRef{Commit: commit, Path: path}, content, ignores)
	}
}

// scanIndexPaths scans the staged version of each path, reading from the index
// rather than the working tree.
func (g *GitScanner) scanIndexPaths(ctx context.Context, paths []string) (Result, error) {
	ignores, err := g.loadIgnore(ctx)
	if err != nil {
		return Result{}, err
	}

	var res Result
	for _, path := range paths {
		blob, err := g.run(ctx, "show", ":"+path)
		if err != nil {
			res.Errs = append(res.Errs, err)
			continue
		}
		g.appendFindings(ctx, &res, GitRef{Path: path}, blob, ignores)
	}
	return res, nil
}

// appendFindings scans one blob and records what it held.
func (g *GitScanner) appendFindings(ctx context.Context, res *Result, ref GitRef, content []byte, ignores Stack) {
	// Path rules in .vedeiignore apply to history and diffs as they do to a tree
	// scan. Without this, a path rule silenced a file in "vedei scan" and the
	// same file was still reported by "vedei diff" — the mode CI runs on every
	// pull request.
	if ignores.Ignored(ref.Path, false) {
		res.Skipped++
		return
	}
	if g.scanner.maxFileSize > 0 && int64(len(content)) > g.scanner.maxFileSize {
		res.Skipped++
		return
	}
	if isBinary(content) {
		res.Skipped++
		return
	}

	res.Scanned++
	res.Bytes += int64(len(content))

	findings, err := g.scanner.engine.Scan(ctx, content, detect.Metadata{
		Path:   ref.Path,
		Source: "git",
		Extra:  map[string]string{"commit": ref.Commit},
	})
	if err != nil {
		res.Errs = append(res.Errs, fmt.Errorf("scan: %s: %w", ref, err))
		return
	}

	// The location carries the ref, not just the path: a finding in a commit
	// that no longer has the file needs the commit to be found again.
	label := ref.String()
	for i := range findings {
		for j := range findings[i].Locations {
			findings[i].Locations[j].Path = label
		}
	}

	kept, silenced := filterIgnored(findings, ignores)
	res.Ignored += silenced
	if len(kept) > 0 {
		res.Files = append(res.Files, FileResult{Path: label, Findings: kept})
	}
}

// loadIgnore reads .vedeiignore from the working tree.
//
// From the working tree and not from the commit being scanned, deliberately: an
// ignore entry is a statement about what the maintainers accept today, not about
// what a commit from two years ago happened to contain.
func (g *GitScanner) loadIgnore(_ context.Context) (Stack, error) {
	ig, err := LoadIgnore(g.repo+"/.vedeiignore", "")
	if err != nil {
		return nil, err
	}
	if ig == nil {
		return nil, nil
	}
	return Stack{ig}, nil
}

// splitNUL splits git's -z output, which is NUL-terminated rather than
// newline-separated so a path with a newline in it survives.
func splitNUL(b []byte) []string {
	var out []string
	for _, part := range bytes.Split(b, []byte{0}) {
		if s := string(part); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// parseLsTree reads one entry of "git ls-tree -r --long":
//
//	100644 blob a1b2c3...    1234\tpath/to/file
//
// Only blobs are returned; a tree, a submodule commit or a symlink entry is
// skipped.
func parseLsTree(entry string) (blob, path string, size int64, ok bool) {
	tab := strings.IndexByte(entry, '\t')
	if tab < 0 {
		return "", "", 0, false
	}
	meta, path := entry[:tab], entry[tab+1:]

	fields := strings.Fields(meta)
	if len(fields) != 4 || fields[1] != "blob" {
		return "", "", 0, false
	}
	// Mode 120000 is a symlink: its blob holds the target, not content.
	if fields[0] == "120000" {
		return "", "", 0, false
	}
	size, err := strconv.ParseInt(fields[3], 10, 64)
	if err != nil {
		return "", "", 0, false
	}
	return fields[2], path, size, true
}
