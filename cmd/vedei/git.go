package main

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/mkmuniz/vedei/engine"
	"github.com/mkmuniz/vedei/report"
	"github.com/mkmuniz/vedei/scan"
)

// gitOpts are the flags the git-backed commands share with scan.
type gitOpts struct {
	format        string
	out           string
	maxFileSize   int64
	brOnly        bool
	minConfidence string
}

func (o *gitOpts) bind(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&o.format, "format", "f", string(report.FormatTable),
		fmt.Sprintf("output format %v", report.Formats))
	cmd.Flags().StringVarP(&o.out, "out", "o", "", "write the report to this file instead of stdout")
	cmd.Flags().Int64Var(&o.maxFileSize, "max-file-size", scan.DefaultMaxFileSize,
		"skip blobs larger than this many bytes (0 for no limit)")
	cmd.Flags().BoolVar(&o.brOnly, "br-only", false,
		"only Brazilian data, skipping the secret rule set")
	cmd.Flags().StringVar(&o.minConfidence, "min-confidence", "low",
		"report only findings at this confidence or above (low, medium, high)")
}

// gitScanner builds the scanner the git commands use.
func (o *gitOpts) gitScanner(repo string) (*scan.GitScanner, error) {
	eng := engine.Offline()
	if o.brOnly {
		eng = engine.BrazilianOnly()
	}
	return scan.NewGitScanner(scan.NewScanner(eng, scan.WithMaxFileSize(o.maxFileSize)), repo)
}

func newGitCmd() *cobra.Command {
	var (
		opts gitOpts
		revs []string
	)

	cmd := &cobra.Command{
		Use:   "git [repo]",
		Short: "Scan a repository's history, including commits that no longer have the file",
		Long: `Walks every blob reachable from the given revisions.

This is the command that finds the common case: a credential that was committed
and then deleted. Removing it from the working tree is what people do instead of
rotating it, and the blob is still there — "vedei scan" will not see it, and
neither will a reviewer.

A blob reachable from several commits is scanned once, which on a real
repository is the difference between minutes and hours.

.vedeiignore is read from the working tree, not from the commit being scanned:
an ignore entry states what the maintainers accept today, not what a commit from
two years ago happened to contain.

Needs git on PATH. vedei drives the git binary rather than reimplementing it,
so partial clones, worktrees, LFS and submodules behave exactly as your own git
does.`,
		Args:          cobra.MaximumNArgs(1),
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			repo := "."
			if len(args) == 1 {
				repo = args[0]
			}
			return runGitScan(cmd, &opts, repo, "history", func(ctx context.Context, g *scan.GitScanner) (scan.Result, error) {
				return g.History(ctx, revs...)
			})
		},
	}

	opts.bind(cmd)
	cmd.Flags().StringSliceVar(&revs, "rev", nil,
		"revisions to walk (default --all, meaning every branch and tag)")
	return cmd
}

func newDiffCmd() *cobra.Command {
	var (
		opts   gitOpts
		repo   string
		base   string
		head   string
		staged bool
	)

	cmd := &cobra.Command{
		Use:   "diff",
		Short: "Scan staged changes, or the files that changed between two revisions",
		Long: `Two modes, for the two places this belongs.

  vedei diff --staged           what is about to be committed
  vedei diff --base X --head Y  what changed between two revisions

--staged reads the index rather than the working tree, which is what a
pre-commit hook needs: a secret you edited but did not stage is not part of this
commit, and blocking on it would be wrong. It is also why the staged content is
what gets scanned even after you clean up the file.

--base/--head is what CI wants. Re-scanning the whole history on every push is
how a secret scanner becomes the slowest step in the pipeline, and everything
before the base was already scanned once. Use "vedei git" for the full history,
deliberately, on a schedule.`,
		Args:          cobra.NoArgs,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if staged && (base != "" || head != "") {
				return fmt.Errorf("--staged and --base/--head are different questions; pick one")
			}
			if !staged && base == "" {
				return fmt.Errorf("give --staged, or --base with an optional --head")
			}

			label := "staged"
			fn := func(ctx context.Context, g *scan.GitScanner) (scan.Result, error) {
				return g.Staged(ctx)
			}
			if !staged {
				if head == "" {
					head = "HEAD"
				}
				label = base + ".." + head
				fn = func(ctx context.Context, g *scan.GitScanner) (scan.Result, error) {
					return g.Diff(ctx, base, head)
				}
			}
			return runGitScan(cmd, &opts, repo, label, fn)
		},
	}

	opts.bind(cmd)
	cmd.Flags().StringVar(&repo, "repo", ".", "repository to scan")
	cmd.Flags().BoolVar(&staged, "staged", false, "scan what is staged for commit")
	cmd.Flags().StringVar(&base, "base", "", "revision to compare from")
	cmd.Flags().StringVar(&head, "head", "", "revision to compare to (default HEAD)")
	return cmd
}

// runGitScan is the shared body: build the scanner, run it, report, exit.
func runGitScan(cmd *cobra.Command, opts *gitOpts, repo, target string,
	fn func(context.Context, *scan.GitScanner) (scan.Result, error),
) error {
	f, err := report.ParseFormat(opts.format)
	if err != nil {
		return err
	}
	minConf, err := parseConfidence(opts.minConfidence)
	if err != nil {
		return err
	}

	g, err := opts.gitScanner(repo)
	if err != nil {
		return err
	}

	started := time.Now()
	res, err := fn(cmd.Context(), g)
	if err != nil {
		return err
	}

	run := report.Run{
		Tool:     "vedei",
		Version:  version,
		Target:   target,
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

	w, closeOut, err := output(opts.out)
	if err != nil {
		return err
	}
	defer closeOut()

	if err := report.Write(w, f, run); err != nil {
		return err
	}

	if len(res.Errs) > 0 {
		return fmt.Errorf("%d blob(s) could not be scanned", len(res.Errs))
	}
	if n := len(run.Findings); n > 0 {
		return findingsError{n: n}
	}
	return nil
}
