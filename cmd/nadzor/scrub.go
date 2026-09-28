package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/mkmuniz/nadzor/engine"
	"github.com/mkmuniz/nadzor/transcript"
)

func newTranscriptScrubCmd() *cobra.Command {
	var (
		path     string
		dryRun   bool
		yes      bool
		noBackup bool
		annotate bool
	)

	cmd := &cobra.Command{
		Use:   "scrub",
		Short: "Rewrite agent transcripts with every detected value masked",
		Long: `Removes sensitive values from the session logs that already hold them.

This is the only command that modifies a file you did not hand it, so it is the
only one that asks first:

  nadzor transcript scrub --dry-run     see exactly what would change
  nadzor transcript scrub               do it, after confirming

Each file is copied to <name>.nadzor-backup-<timestamp> and the copy is verified
by hash before anything is written. The rewrite goes to a new file beside the
original and is renamed over it only after every record is confirmed to still
parse and the record count is confirmed unchanged — so a failure leaves the
original exactly as it was.

Close your agent sessions first. nadzor cannot tell whether something is
appending to a transcript while it is being rewritten, and will not pretend to.`,
		Args:          cobra.NoArgs,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			roots, err := scrubRoots(path)
			if err != nil {
				return err
			}

			files, err := transcriptFiles(roots)
			if err != nil {
				return err
			}
			if len(files) == 0 {
				_, _ = fmt.Fprintln(cmd.OutOrStdout(), "no transcripts found")
				return nil
			}

			sc := transcript.NewScanner(engine.Offline())

			// The dry run is not optional in spirit: without --yes, this asks,
			// and it asks after showing what it found rather than before.
			plans := make([]scrubPlan, 0, len(files))
			for _, f := range files {
				res, err := sc.Scrub(cmd.Context(), f.agent, f.path,
					transcript.ScrubOptions{DryRun: true, Annotate: annotate})
				if err != nil {
					return err
				}
				if res.Replacements > 0 {
					plans = append(plans, scrubPlan{file: f, result: res})
				}
			}

			if len(plans) == 0 {
				_, _ = fmt.Fprintf(cmd.OutOrStdout(),
					"%d transcript(s) checked, nothing to remove\n", len(files))
				return nil
			}

			printScrubPlan(cmd.OutOrStdout(), plans)

			if dryRun {
				_, _ = fmt.Fprintln(cmd.OutOrStdout(), "\n--dry-run: nothing was written.")
				return nil
			}
			if !yes {
				ok, err := confirm(cmd.InOrStdin(), cmd.OutOrStdout(),
					fmt.Sprintf("Rewrite %d transcript(s)?", len(plans)))
				if err != nil {
					return err
				}
				if !ok {
					_, _ = fmt.Fprintln(cmd.OutOrStdout(), "cancelled, nothing was written")
					return nil
				}
			}

			return applyScrub(cmd, sc, plans, noBackup, annotate)
		},
	}

	cmd.Flags().StringVar(&path, "path", "", "scrub this file or directory instead of the default agent locations")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "report what would change and write nothing")
	cmd.Flags().BoolVar(&yes, "yes", false, "skip the confirmation prompt")
	cmd.Flags().BoolVar(&noBackup, "no-backup", false,
		"do not keep a copy of the original (you will not be able to undo this)")
	cmd.Flags().BoolVar(&annotate, "annotate", true,
		"mark each replacement, so a later reader knows why a value looks like that")
	return cmd
}

// applyScrub rewrites the files in the plan, reporting each one as it goes.
//
// A failure stops the run rather than continuing: if the first rewrite went
// wrong, the reason is likely to apply to the rest, and half-scrubbed
// transcripts are harder to reason about than none.
func applyScrub(cmd *cobra.Command, sc *transcript.Scanner,
	plans []scrubPlan, noBackup, annotate bool,
) error {
	out := cmd.OutOrStdout()
	total := 0

	for _, plan := range plans {
		res, err := sc.Scrub(cmd.Context(), plan.file.agent, plan.file.path, transcript.ScrubOptions{
			NoBackup: noBackup,
			Annotate: annotate,
		})
		if err != nil {
			return err
		}
		total += res.Replacements

		line := fmt.Sprintf("%s: %d value(s) removed from %d record(s)",
			shorten(res.Path), res.Replacements, res.LinesChanged)
		if res.Backup != "" {
			line += ", backup at " + shorten(res.Backup)
		}
		_, _ = fmt.Fprintln(out, line)
	}

	_, _ = fmt.Fprintf(out, "\n%d value(s) removed from %d transcript(s).\n", total, len(plans))
	if noBackup {
		_, _ = fmt.Fprintln(out, "No backups were kept.")
	} else {
		_, _ = fmt.Fprintln(out, "Delete the backups once you are satisfied — they still hold the values.")
	}
	return nil
}

// scrubPlan is what the dry run found for one file, kept with the file so the
// second pass does not have to recover the agent from a finding's metadata.
type scrubPlan struct {
	file   transcriptFile
	result transcript.ScrubResult
}

func printScrubPlan(w io.Writer, plans []scrubPlan) {
	values, records := 0, 0
	for _, p := range plans {
		values += p.result.Replacements
		records += p.result.LinesChanged
	}

	_, _ = fmt.Fprintf(w, "%d value(s) in %d record(s) across %d transcript(s):\n\n", values, records, len(plans))
	for _, p := range plans {
		types := map[string]int{}
		for _, f := range p.result.Findings {
			types[f.Type] += len(f.Locations)
		}
		parts := make([]string, 0, len(types))
		for t, n := range types {
			parts = append(parts, fmt.Sprintf("%d %s", n, t))
		}
		sortStrings(parts)
		_, _ = fmt.Fprintf(w, "  %s\n    %s\n", shorten(p.file.path), strings.Join(parts, ", "))
	}
}

// transcriptFile pairs a path with the agent that wrote it, so a scrub can
// record which agent a finding came from.
type transcriptFile struct {
	agent transcript.Agent
	path  string
}

// scrubRoots resolves what to scrub: an explicit --path, or the default agent
// locations.
func scrubRoots(path string) (map[transcript.Agent]string, error) {
	if path == "" {
		roots := transcript.DefaultRoots()
		if len(roots) == 0 {
			return nil, fmt.Errorf("no agent transcript directory found; pass --path")
		}
		return roots, nil
	}
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return map[transcript.Agent]string{transcript.Agent("custom"): path}, nil
}

// transcriptFiles lists the .jsonl files under each root, or the root itself
// when it is a file.
func transcriptFiles(roots map[transcript.Agent]string) ([]transcriptFile, error) {
	var out []transcriptFile

	for agent, root := range roots {
		info, err := os.Stat(root)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", root, err)
		}
		if !info.IsDir() {
			out = append(out, transcriptFile{agent: agent, path: root})
			continue
		}

		err = filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(d.Name(), ".jsonl") {
				return nil
			}
			// A backup still holds the values, so scrubbing one is pointless and
			// scrubbing it in place would destroy the copy of the original.
			if strings.Contains(d.Name(), ".nadzor-backup-") {
				return nil
			}
			out = append(out, transcriptFile{agent: agent, path: p})
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("walking %s: %w", root, err)
		}
	}

	sortFiles(out)
	return out, nil
}

// confirm asks a yes/no question. Anything but an explicit yes is a no.
func confirm(in io.Reader, out io.Writer, question string) (bool, error) {
	_, _ = fmt.Fprintf(out, "\n%s [y/N] ", question)

	r := bufio.NewReader(in)
	line, err := r.ReadString('\n')
	if err != nil && line == "" {
		// No answer — a closed stdin, a pipe with nothing in it. Treated as no,
		// because a destructive default of yes is how people lose data.
		return false, nil
	}
	answer := strings.ToLower(strings.TrimSpace(line))
	return answer == "y" || answer == "yes", nil
}
