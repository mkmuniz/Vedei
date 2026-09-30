package scan_test

import (
	"context"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mkmuniz/vedei/engine"
	"github.com/mkmuniz/vedei/scan"
)

// benchWords make the synthetic tree look like source rather than random bytes.
// That matters: the engines prefilter on shape, so a tree of random characters
// measures the prefilter and a tree of English-looking tokens measures the scan.
var benchWords = []string{
	"func", "return", "error", "import", "package", "string", "context",
	"handler", "request", "response", "config", "value", "client", "server",
	"result", "buffer", "stream", "engine", "scanner", "report",
}

// benchTree writes files of source-shaped text and returns the root and its
// total size.
func benchTree(tb testing.TB, files, linesPerFile int) (root string, bytes int64) {
	tb.Helper()
	root = tb.TempDir()
	r := rand.New(rand.NewPCG(42, 42)) //nolint:gosec // a fixture, not a secret

	for i := range files {
		dir := filepath.Join(root, fmt.Sprintf("pkg%d", i/30), fmt.Sprintf("sub%d", i/10))
		if err := os.MkdirAll(dir, 0o750); err != nil {
			tb.Fatalf("MkdirAll: %v", err)
		}

		var b strings.Builder
		for range linesPerFile {
			for w := 0; w < 12; w++ {
				if w > 0 {
					b.WriteByte(' ')
				}
				b.WriteString(benchWords[r.IntN(len(benchWords))])
			}
			b.WriteByte('\n')
		}
		// One file in fifty holds something, so the reporting path is measured
		// too rather than only the clean path.
		if i%50 == 0 {
			b.WriteString("cpf " + testCPF + "\n")
		}

		body := b.String()
		p := filepath.Join(dir, fmt.Sprintf("file%d.go", i))
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			tb.Fatalf("WriteFile: %v", err)
		}
		bytes += int64(len(body))
	}
	return root, bytes
}

// BenchmarkScanTree reports throughput over a tree of source-shaped files.
//
// M4 asks for more than 50 MB/s. Measured on an Apple M4 over 9.8 MB in 300
// files, three ways, because they answer different questions:
//
//	218 MB/s   warm, in-process, both engines   (this benchmark)
//	246 MB/s   warm, in-process, Brazilian only (the next benchmark)
//	 99 MB/s   one CLI run, as the command reports its own elapsed time
//	 72 MB/s   the same CLI run, wall clock, ~137 ms
//
// The gap between the first and the third is one-off cost the benchmark
// amortizes and a command-line user pays every time: compiling 417 secret rules
// on first use, plus loading a 26 MB binary. The gap between the third and the
// fourth is process startup. Quoting only the 218 would be quoting the number
// nobody experiences.
//
// The secret rules cost about 13% here, which is lower than it sounds: most
// files hold nothing their prefilters can latch onto.
//
// These are reported and not asserted. CI runs on shared hardware where an
// absolute MB/s floor measures the runner rather than the code, and that lesson
// already cost one red build.
func BenchmarkScanTree(b *testing.B) {
	root, total := benchTree(b, 300, 400)
	sc := scan.NewScanner(engine.Offline())
	ctx := context.Background()

	b.SetBytes(total)
	b.ResetTimer()
	for range b.N {
		if _, err := sc.Scan(ctx, root); err != nil {
			b.Fatalf("Scan: %v", err)
		}
	}
	b.StopTimer()

	seconds := b.Elapsed().Seconds() / float64(b.N)
	b.ReportMetric(float64(total)/seconds/(1<<20), "MB/s")
}

// BenchmarkScanTreeBrazilianOnly separates the two costs: how much of the time
// is the Brazilian engine and how much is the 417 secret rules.
func BenchmarkScanTreeBrazilianOnly(b *testing.B) {
	root, total := benchTree(b, 300, 400)
	sc := scan.NewScanner(engine.BrazilianOnly())
	ctx := context.Background()

	b.SetBytes(total)
	b.ResetTimer()
	for range b.N {
		if _, err := sc.Scan(ctx, root); err != nil {
			b.Fatalf("Scan: %v", err)
		}
	}
	b.StopTimer()

	seconds := b.Elapsed().Seconds() / float64(b.N)
	b.ReportMetric(float64(total)/seconds/(1<<20), "MB/s")
}
