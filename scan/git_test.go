package scan_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mkmuniz/nadzor/engine"
	"github.com/mkmuniz/nadzor/scan"
)

// gitRepo creates a repository with a local identity, so these tests never
// depend on the machine's git config.
func gitRepo(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	dir := t.TempDir()
	for _, args := range [][]string{
		{"init", "-q", "-b", "main"},
		{"config", "user.name", "nadzor test"},
		{"config", "user.email", "test@example.invalid"},
		{"config", "commit.gpgsign", "false"},
	} {
		git(t, dir, args...)
	}
	return dir
}

func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.CommandContext(context.Background(), "git", append([]string{"-C", dir}, args...)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

func writeFile(t *testing.T, dir, rel, body string) {
	t.Helper()
	p := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
}

func gitScanner(t *testing.T, repo string) *scan.GitScanner {
	t.Helper()
	g, err := scan.NewGitScanner(scan.NewScanner(engine.Offline()), repo)
	if err != nil {
		t.Fatalf("NewGitScanner: %v", err)
	}
	return g
}

// Staged reads the index, not the working tree: a secret edited but not staged
// is not what this commit is about, and blocking on it would be wrong.
func TestStaged_ReadsTheIndexNotTheWorkingTree(t *testing.T) {
	repo := gitRepo(t)
	writeFile(t, repo, "staged.txt", "cpf "+testCPF)
	git(t, repo, "add", "staged.txt")
	writeFile(t, repo, "unstaged.txt", "cpf "+testCPF)

	res, err := gitScanner(t, repo).Staged(context.Background())
	if err != nil {
		t.Fatalf("Staged: %v", err)
	}
	if res.Total() != 1 {
		t.Fatalf("Total() = %d, want 1: %v", res.Total(), res.Files)
	}
	if got := res.Files[0].Path; got != "staged.txt" {
		t.Errorf("path = %q, want staged.txt", got)
	}
}

// The staged version is what matters, even when the working tree has since been
// cleaned up. This is the case a pre-commit hook exists for.
func TestStaged_UsesTheStagedContent(t *testing.T) {
	repo := gitRepo(t)
	writeFile(t, repo, "a.txt", "cpf "+testCPF)
	git(t, repo, "add", "a.txt")
	writeFile(t, repo, "a.txt", "cleaned up")

	res, err := gitScanner(t, repo).Staged(context.Background())
	if err != nil {
		t.Fatalf("Staged: %v", err)
	}
	if res.Total() != 1 {
		t.Errorf("Total() = %d, want 1 — the staged blob still has it", res.Total())
	}
}

func TestStaged_NothingStaged(t *testing.T) {
	repo := gitRepo(t)
	writeFile(t, repo, "a.txt", "cpf "+testCPF)

	res, err := gitScanner(t, repo).Staged(context.Background())
	if err != nil {
		t.Fatalf("Staged: %v", err)
	}
	if res.Total() != 0 || res.Scanned != 0 {
		t.Errorf("Total() = %d, Scanned = %d, want 0 and 0", res.Total(), res.Scanned)
	}
}

// The case that matters most: a credential committed and then removed. Removing
// it from the working tree is what people do instead of rotating it, and the
// blob is still in the history.
func TestHistory_FindsASecretThatWasRemoved(t *testing.T) {
	repo := gitRepo(t)
	writeFile(t, repo, "config.yml", "cpf "+testCPF)
	git(t, repo, "add", ".")
	git(t, repo, "commit", "-qm", "add config")

	writeFile(t, repo, "config.yml", "nothing here any more")
	git(t, repo, "add", ".")
	git(t, repo, "commit", "-qm", "remove the value")

	// The working tree is clean now.
	if res := run(t, repo, scan.WithDefaultIgnores(false)); res.Total() != 0 {
		t.Fatalf("the working tree should be clean, got %d", res.Total())
	}

	res, err := gitScanner(t, repo).History(context.Background())
	if err != nil {
		t.Fatalf("History: %v", err)
	}
	if res.Total() == 0 {
		t.Fatal("History missed a value that is still in a past commit")
	}
	// The report has to name the commit, or the finding cannot be found again.
	if got := res.Files[0].Path; !strings.Contains(got, ":config.yml") {
		t.Errorf("path = %q, want commit:config.yml", got)
	}
}

// One blob reachable from many commits is scanned once. On a real repository
// this is the difference between minutes and hours.
func TestHistory_ScansEachBlobOnce(t *testing.T) {
	repo := gitRepo(t)
	writeFile(t, repo, "secret.txt", "cpf "+testCPF)
	writeFile(t, repo, "other.txt", "a")
	git(t, repo, "add", ".")
	git(t, repo, "commit", "-qm", "first")

	for i := range 4 {
		writeFile(t, repo, "other.txt", strings.Repeat("b", i+1))
		git(t, repo, "add", ".")
		git(t, repo, "commit", "-qm", "touch other")
	}

	res, err := gitScanner(t, repo).History(context.Background())
	if err != nil {
		t.Fatalf("History: %v", err)
	}
	// 5 commits, but only 6 distinct blobs: secret.txt once and other.txt five
	// times. Without deduplication this would be 10.
	if res.Scanned > 6 {
		t.Errorf("Scanned = %d, want at most 6 — blobs are not deduplicated", res.Scanned)
	}
	if res.Total() != 1 {
		t.Errorf("Total() = %d, want 1", res.Total())
	}
}

func TestHistory_SkipsBinaryBlobs(t *testing.T) {
	repo := gitRepo(t)
	writeFile(t, repo, "a.bin", "cpf "+testCPF+"\x00")
	git(t, repo, "add", ".")
	git(t, repo, "commit", "-qm", "binary")

	res, err := gitScanner(t, repo).History(context.Background())
	if err != nil {
		t.Fatalf("History: %v", err)
	}
	if res.Total() != 0 {
		t.Errorf("Total() = %d, want 0", res.Total())
	}
	if res.Skipped == 0 {
		t.Error("the binary blob was not counted as skipped")
	}
}

func TestDiff_OnlyTheChangedFiles(t *testing.T) {
	repo := gitRepo(t)
	writeFile(t, repo, "old.txt", "cpf "+testCPF)
	git(t, repo, "add", ".")
	git(t, repo, "commit", "-qm", "first")
	base := git(t, repo, "rev-parse", "HEAD")

	writeFile(t, repo, "new.txt", "cnpj 11.222.333/0001-81")
	git(t, repo, "add", ".")
	git(t, repo, "commit", "-qm", "second")

	res, err := gitScanner(t, repo).Diff(context.Background(), base, "HEAD")
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if res.Total() != 1 {
		t.Fatalf("Total() = %d, want 1 — only the changed file: %v", res.Total(), res.Files)
	}
	if got := res.Files[0].Findings[0].Type; got != "cnpj" {
		t.Errorf("type = %q, want cnpj", got)
	}
}

// A file deleted in head is not a failure: there is nothing to scan.
func TestDiff_HandlesADeletedFile(t *testing.T) {
	repo := gitRepo(t)
	writeFile(t, repo, "gone.txt", "cpf "+testCPF)
	git(t, repo, "add", ".")
	git(t, repo, "commit", "-qm", "first")
	base := git(t, repo, "rev-parse", "HEAD")

	git(t, repo, "rm", "-q", "gone.txt")
	git(t, repo, "commit", "-qm", "delete it")

	res, err := gitScanner(t, repo).Diff(context.Background(), base, "HEAD")
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if res.Total() != 0 {
		t.Errorf("Total() = %d, want 0", res.Total())
	}
}

// An ignore entry is a statement about what the maintainers accept today, not
// about what a commit from two years ago contained, so it is read from the
// working tree.
func TestHistory_NadzorignoreComesFromTheWorkingTree(t *testing.T) {
	repo := gitRepo(t)
	writeFile(t, repo, "a.txt", "cpf "+testCPF)
	git(t, repo, "add", ".")
	git(t, repo, "commit", "-qm", "first")

	before, err := gitScanner(t, repo).History(context.Background())
	if err != nil {
		t.Fatalf("History: %v", err)
	}
	if before.Total() != 1 {
		t.Fatalf("Total() = %d, want 1 before the ignore file exists", before.Total())
	}

	// Not committed — only in the working tree.
	writeFile(t, repo, ".nadzorignore", before.Findings()[0].Fingerprint+"  # test fixture\n")

	after, err := gitScanner(t, repo).History(context.Background())
	if err != nil {
		t.Fatalf("History: %v", err)
	}
	if after.Total() != 0 {
		t.Errorf("Total() = %d, want 0 — the uncommitted ignore file should apply", after.Total())
	}
	if after.Ignored != 1 {
		t.Errorf("Ignored = %d, want 1", after.Ignored)
	}
}

func TestNewGitScanner_NotARepository(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	g, err := scan.NewGitScanner(scan.NewScanner(engine.Offline()), t.TempDir())
	if err != nil {
		t.Fatalf("NewGitScanner: %v", err)
	}
	if _, err := g.History(context.Background()); err == nil {
		t.Fatal("scanning a non-repository returned no error")
	}
}

func TestGitRef_String(t *testing.T) {
	cases := map[scan.GitRef]string{
		{Commit: "a1b2c3d4e5f6a7b8c9d0", Path: "cfg.yml"}: "a1b2c3d4e5f6:cfg.yml",
		{Path: "staged.yml"}:                              "staged.yml",
		{Commit: "abc", Path: "x"}:                        "abc:x",
	}
	for ref, want := range cases {
		if got := ref.String(); got != want {
			t.Errorf("%+v.String() = %q, want %q", ref, got, want)
		}
	}
}
