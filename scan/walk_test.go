package scan_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mkmuniz/vedei/detect"
	"github.com/mkmuniz/vedei/engine"
	"github.com/mkmuniz/vedei/fingerprint"
	"github.com/mkmuniz/vedei/scan"
)

const testCPF = "529.982.247-25"

// tree writes a set of files and returns the root. Keys are slash-separated
// relative paths; a key ending in "/" is an empty directory.
func tree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for rel, body := range files {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if strings.HasSuffix(rel, "/") {
			if err := os.MkdirAll(p, 0o750); err != nil {
				t.Fatalf("MkdirAll: %v", err)
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
	}
	return root
}

func run(t *testing.T, root string, opts ...scan.Option) scan.Result {
	t.Helper()
	res, err := scan.NewScanner(engine.Offline(), opts...).Scan(context.Background(), root)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	return res
}

// pathsWithFindings returns the paths that produced findings. They are already
// relative to the scan root, which is what SARIF needs.
func pathsWithFindings(_ string, res scan.Result) []string {
	var out []string
	for _, f := range res.Files {
		out = append(out, f.Path)
	}
	return out
}

func TestScan_FindsInATree(t *testing.T) {
	root := tree(t, map[string]string{
		"a.txt":       "cpf " + testCPF,
		"sub/b.txt":   "nada aqui",
		"sub/c.env":   "cpf " + testCPF,
		"clean/d.txt": "texto limpo",
	})

	res := run(t, root)
	if got, want := res.Total(), 2; got != want {
		t.Fatalf("Total() = %d, want %d: %v", got, want, pathsWithFindings(root, res))
	}
	if res.Scanned != 4 {
		t.Errorf("Scanned = %d, want 4", res.Scanned)
	}
	// Results are in walk order regardless of which worker finished first.
	if got := pathsWithFindings(root, res); got[0] != "a.txt" || got[1] != "sub/c.env" {
		t.Errorf("order = %v", got)
	}
}

// A single file as root is what a person types first.
func TestScan_SingleFile(t *testing.T) {
	root := tree(t, map[string]string{"a.txt": "cpf " + testCPF})

	res := run(t, filepath.Join(root, "a.txt"))
	if res.Total() != 1 {
		t.Fatalf("Total() = %d, want 1", res.Total())
	}
	if res.Scanned != 1 {
		t.Errorf("Scanned = %d, want 1", res.Scanned)
	}
}

// Every location has to carry its path, or a report names a type and no file.
func TestScan_FindingsCarryTheirPath(t *testing.T) {
	root := tree(t, map[string]string{"deep/a.txt": "cpf " + testCPF})

	res := run(t, root)
	for _, f := range res.Files {
		for _, finding := range f.Findings {
			if len(finding.Locations) == 0 {
				t.Fatalf("%s has no locations", finding.Type)
			}
			for _, loc := range finding.Locations {
				if loc.Path == "" {
					t.Errorf("%s: a location has no path", finding.Type)
				}
				if loc.Line == 0 {
					t.Errorf("%s: a location has no line", finding.Type)
				}
			}
		}
	}
}

func TestScan_HonoursGitignore(t *testing.T) {
	root := tree(t, map[string]string{
		".gitignore":     "ignored/\n*.bak\n",
		"kept.txt":       "cpf " + testCPF,
		"ignored/x.txt":  "cpf " + testCPF,
		"notes.txt.bak":  "cpf " + testCPF,
		"sub/.gitignore": "!*.bak\n",
		"sub/notes.bak":  "cpf " + testCPF,
	})

	res := run(t, root)
	got := pathsWithFindings(root, res)
	want := map[string]bool{"kept.txt": true, "sub/notes.bak": true}
	if len(got) != len(want) {
		t.Fatalf("paths = %v, want %v", got, want)
	}
	for _, p := range got {
		if !want[p] {
			t.Errorf("unexpected path %q", p)
		}
	}
}

func TestScan_GitignoreCanBeDisabled(t *testing.T) {
	root := tree(t, map[string]string{
		".gitignore": "secret.txt\n",
		"secret.txt": "cpf " + testCPF,
	})

	if res := run(t, root); res.Total() != 0 {
		t.Errorf("with .gitignore honoured: Total() = %d, want 0", res.Total())
	}
	if res := run(t, root, scan.WithGitignore(false)); res.Total() != 1 {
		t.Errorf("with --no-gitignore: Total() = %d, want 1", res.Total())
	}
}

// A credential committed into vendor/ is still committed, so the default skip
// list has to be something a caller can turn off.
func TestScan_DefaultIgnoresCanBeDisabled(t *testing.T) {
	root := tree(t, map[string]string{
		"node_modules/pkg/a.js": "cpf " + testCPF,
		"app.js":                "texto limpo",
	})

	if res := run(t, root); res.Total() != 0 {
		t.Errorf("by default node_modules should be skipped, got %d", res.Total())
	}
	if res := run(t, root, scan.WithDefaultIgnores(false)); res.Total() != 1 {
		t.Errorf("with defaults off: Total() = %d, want 1", res.Total())
	}
}

// .git holds packed objects that produce matches meaning nothing.
func TestScan_SkipsTheGitDirectory(t *testing.T) {
	root := tree(t, map[string]string{
		".git/objects/x": "cpf " + testCPF,
		"a.txt":          "texto limpo",
	})
	if res := run(t, root); res.Total() != 0 {
		t.Errorf("Total() = %d, want 0", res.Total())
	}
}

func TestScan_SkipsBinaryFiles(t *testing.T) {
	root := tree(t, map[string]string{
		"a.bin": "cpf " + testCPF + "\x00 binary",
		"b.txt": "cpf " + testCPF,
	})

	res := run(t, root)
	if res.Total() != 1 {
		t.Fatalf("Total() = %d, want 1: %v", res.Total(), pathsWithFindings(root, res))
	}
	if got := pathsWithFindings(root, res); got[0] != "b.txt" {
		t.Errorf("scanned %q, want b.txt", got[0])
	}
}

func TestScan_SkipsFilesOverTheSizeCap(t *testing.T) {
	root := tree(t, map[string]string{
		"big.txt":   strings.Repeat("x", 2048) + " cpf " + testCPF,
		"small.txt": "cpf " + testCPF,
	})

	res := run(t, root, scan.WithMaxFileSize(1024))
	if res.Total() != 1 {
		t.Fatalf("Total() = %d, want 1: %v", res.Total(), pathsWithFindings(root, res))
	}
}

// A symlink is skipped by default: one pointing outside the tree makes a scan
// report paths nobody asked about, and a cycle makes it never finish.
func TestScan_SkipsSymlinksByDefault(t *testing.T) {
	root := tree(t, map[string]string{"real.txt": "cpf " + testCPF})
	if err := os.Symlink(filepath.Join(root, "real.txt"), filepath.Join(root, "link.txt")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	res := run(t, root)
	if res.Total() != 1 {
		t.Errorf("Total() = %d, want 1 (the real file only)", res.Total())
	}
	if res.Skipped != 1 {
		t.Errorf("Skipped = %d, want 1", res.Skipped)
	}
}

// A .vedeiignore fingerprint silences a value wherever it appears, which is
// the point: it has to survive the file being moved or renamed.
func TestScan_VedeiignoreSilencesByFingerprint(t *testing.T) {
	fp := fingerprint.Of("cpf", testCPF)
	root := tree(t, map[string]string{
		".vedeiignore": fp + "  # the CPF in our fixtures\n",
		"a.txt":         "cpf " + testCPF,
		"moved/b.txt":   "cpf " + testCPF,
	})

	res := run(t, root)
	if res.Total() != 0 {
		t.Errorf("Total() = %d, want 0: %v", res.Total(), pathsWithFindings(root, res))
	}
	if res.Ignored != 2 {
		t.Errorf("Ignored = %d, want 2 — both occurrences should be counted", res.Ignored)
	}
}

func TestScan_VedeiignorePathRules(t *testing.T) {
	root := tree(t, map[string]string{
		".vedeiignore":  "testdata/\n",
		"testdata/a.txt": "cpf " + testCPF,
		"b.txt":          "cpf " + testCPF,
	})

	res := run(t, root)
	if res.Total() != 1 {
		t.Fatalf("Total() = %d, want 1: %v", res.Total(), pathsWithFindings(root, res))
	}
}

// Fails closed, per ADR-005: a scan that could not read part of the tree must
// not report clean.
func TestScan_UnreadableFileIsAnError(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root, which can read anything")
	}
	root := tree(t, map[string]string{"locked.txt": "cpf " + testCPF})
	locked := filepath.Join(root, "locked.txt")
	if err := os.Chmod(locked, 0o000); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o600) })

	res := run(t, root)
	if len(res.Errs) == 0 {
		t.Fatal("an unreadable file produced no error")
	}
	if res.Total() != 0 {
		t.Errorf("Total() = %d", res.Total())
	}
}

func TestScan_MissingRootIsAnError(t *testing.T) {
	_, err := scan.NewScanner(engine.Offline()).Scan(context.Background(), filepath.Join(t.TempDir(), "nope"))
	if err == nil {
		t.Fatal("a missing root returned no error")
	}
}

func TestScan_RespectsContextCancellation(t *testing.T) {
	root := tree(t, map[string]string{"a.txt": "cpf " + testCPF})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := scan.NewScanner(engine.Offline()).Scan(ctx, root)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
}

func TestReader_ScansWithoutAFile(t *testing.T) {
	s := scan.NewScanner(engine.Offline())

	findings, err := s.Reader(context.Background(),
		strings.NewReader("cpf "+testCPF), detect.Metadata{Path: "HEAD:config.yml", Source: "git"})
	if err != nil {
		t.Fatalf("Reader: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(findings))
	}
	if findings[0].Locations[0].Path != "HEAD:config.yml" {
		t.Errorf("path = %q", findings[0].Locations[0].Path)
	}
}

func TestReader_SkipsBinary(t *testing.T) {
	s := scan.NewScanner(engine.Offline())
	findings, err := s.Reader(context.Background(),
		strings.NewReader("cpf "+testCPF+"\x00"), detect.Metadata{})
	if err != nil {
		t.Fatalf("Reader: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("want nothing from a binary blob, got %d", len(findings))
	}
}

// Paths in the report are relative to the scan root. SARIF uploaded to GitHub
// is matched against the repository tree, so an absolute path lands the alert
// on no file at all.
func TestScan_PathsAreRelativeToTheRoot(t *testing.T) {
	root := tree(t, map[string]string{"src/deep/a.txt": "cpf " + testCPF})

	res := run(t, root)
	if len(res.Files) != 1 {
		t.Fatalf("want 1 file, got %d", len(res.Files))
	}
	if got := res.Files[0].Path; got != "src/deep/a.txt" {
		t.Errorf("FileResult.Path = %q, want src/deep/a.txt", got)
	}
	for _, f := range res.Files[0].Findings {
		for _, loc := range f.Locations {
			if loc.Path != "src/deep/a.txt" {
				t.Errorf("Location.Path = %q, want src/deep/a.txt", loc.Path)
			}
			if filepath.IsAbs(loc.Path) {
				t.Errorf("Location.Path is absolute: %q", loc.Path)
			}
		}
	}
}

// A single file keeps the name the caller typed: there is no root for it to be
// relative to, and "." would be useless in a report.
func TestScan_SingleFileKeepsItsName(t *testing.T) {
	root := tree(t, map[string]string{"a.txt": "cpf " + testCPF})
	target := filepath.Join(root, "a.txt")

	res := run(t, target)
	if got := res.Files[0].Path; got != filepath.ToSlash(target) {
		t.Errorf("Path = %q, want %q", got, target)
	}
}
