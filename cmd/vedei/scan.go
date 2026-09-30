package main

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/mkmuniz/vedei/engine"
	"github.com/mkmuniz/vedei/report"
	"github.com/mkmuniz/vedei/scan"
)

func newScanCmd() *cobra.Command {
	var (
		format        string
		out           string
		maxFileSize   int64
		workers       int
		noGitignore   bool
		noDefaults    bool
		followSymlink bool
		brOnly        bool
		minConfidence string
	)

	cmd := &cobra.Command{
		Use:   "scan <path>",
		Short: "Scan a file or directory and report what is in it",
		Long: `Walks a path and reports every Brazilian document and credential in it.

Unlike the hook, this fails closed (ADR-005): a file that could not be read is
an error you hear about, because a scan that silently skipped half a tree and
printed "nothing found" is worse than a red build.

Exit codes: 0 nothing found, 3 findings, 1 the scan itself failed. They are
distinct on purpose — a pipeline that cannot tell a leak from a broken scan
will read a permission error as a clean run.

Ignored by default: .gitignore, plus a list of directories that hold no source
(.git, node_modules, vendor, target, dist and the like). A credential committed
into vendor/ is still committed, so --no-default-ignores turns that off.

.vedeiignore silences a finding by fingerprint, which is derived from the type
and the value and never from the location — so an entry survives the file being
moved or renamed. Path patterns work there too, and decide after .gitignore, so
"!secret.env" forces a scan of something git hides.`,
		Args:          cobra.ExactArgs(1),
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			f, err := report.ParseFormat(format)
			if err != nil {
				return err
			}
			minConf, err := parseConfidence(minConfidence)
			if err != nil {
				return err
			}

			eng := engine.Offline()
			if brOnly {
				eng = engine.BrazilianOnly()
			}

			sc := scan.NewScanner(eng,
				scan.WithMaxFileSize(maxFileSize),
				scan.WithWorkers(workers),
				scan.WithGitignore(!noGitignore),
				scan.WithDefaultIgnores(!noDefaults),
				scan.WithFollowSymlinks(followSymlink),
			)

			started := time.Now()
			res, err := sc.Scan(cmd.Context(), args[0])
			if err != nil {
				return err
			}

			run := report.Run{
				Tool:     "vedei",
				Version:  version,
				Target:   args[0],
				Started:  started,
				Duration: time.Since(started),
				Scanned:  res.Scanned,
				Skipped:  res.Skipped,
				Ignored:  res.Ignored,
				Bytes:    res.Bytes,
				Findings: atLeast(res.Findings(), minConf),
			}
			for _, e := range res.Errs {
				run.Errors = append(run.Errors, e.Error())
			}

			w, closeOut, err := output(out)
			if err != nil {
				return err
			}
			defer closeOut()

			if err := report.Write(w, f, run); err != nil {
				return err
			}

			// A scan that could not read part of the tree reports its findings
			// and still fails: exit 1 outranks exit 3, because "we found two
			// things" is misleading when the scan was incomplete.
			if len(res.Errs) > 0 {
				return fmt.Errorf("%d file(s) could not be scanned", len(res.Errs))
			}
			if n := len(run.Findings); n > 0 {
				return findingsError{n: n}
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&format, "format", "f", string(report.FormatTable),
		fmt.Sprintf("output format %v", report.Formats))
	cmd.Flags().StringVarP(&out, "out", "o", "", "write the report to this file instead of stdout")
	cmd.Flags().Int64Var(&maxFileSize, "max-file-size", scan.DefaultMaxFileSize,
		"skip files larger than this many bytes (0 for no limit)")
	cmd.Flags().IntVar(&workers, "workers", 0, "files to scan in parallel (0 for one per CPU)")
	cmd.Flags().BoolVar(&noGitignore, "no-gitignore", false, "do not honour .gitignore")
	cmd.Flags().BoolVar(&noDefaults, "no-default-ignores", false,
		"also scan .git, node_modules, vendor and the other default skips")
	cmd.Flags().BoolVar(&followSymlink, "follow-symlinks", false,
		"follow symlinks, which can leave the tree or loop forever")
	cmd.Flags().BoolVar(&brOnly, "br-only", false,
		"only Brazilian data, skipping the secret rule set")
	cmd.Flags().StringVar(&minConfidence, "min-confidence", "low",
		"report only findings at this confidence or above (low, medium, high)")
	return cmd
}

// output returns where the report goes, and a function to close it.
//
// Writing to a file rather than redirecting matters for --format sarif, where
// the upload step wants a path and the terminal wants the summary.
func output(path string) (w *os.File, closeFn func(), err error) {
	if path == "" {
		return os.Stdout, func() {}, nil
	}
	f, err := os.Create(path) //#nosec G304 -- --out names the report file; writing where the caller asked is the feature
	if err != nil {
		return nil, nil, fmt.Errorf("creating %s: %w", path, err)
	}
	return f, func() { _ = f.Close() }, nil
}
