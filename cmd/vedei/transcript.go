package main

import (
	"encoding/json"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/mkmuniz/vedei/engine"
	"github.com/mkmuniz/vedei/transcript"
)

func newTranscriptCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "transcript",
		Short: "Audit coding-agent session logs",
	}
	cmd.AddCommand(newTranscriptScanCmd(), newTranscriptScrubCmd())
	return cmd
}

func newTranscriptScanCmd() *cobra.Command {
	var (
		path   string
		asJSON bool
	)

	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Report sensitive data that already reached agent transcripts",
		Long: `Audits the session logs written by Claude Code and Codex.

Those files sit on disk as plaintext: no encryption, no rotation, no expiry,
and no security tool watching them. A .env has file permissions and a
gitignore; a transcript has neither, while aggregating secrets from every
source the agent ever touched. Whoever reads the disk reads all of it.

This command reports. It does not modify anything.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			roots := map[transcript.Agent]string{}
			if path != "" {
				roots[transcript.Agent("custom")] = path
			} else {
				roots = transcript.DefaultRoots()
			}
			if len(roots) == 0 {
				fmt.Fprintln(os.Stderr, "vedei: no agent transcript directory found")
				return nil
			}

			sc := transcript.NewScanner(engine.Offline())
			var all []transcript.Session
			scanned, failures := 0, 0

			for agent, dir := range roots {
				rep, err := sc.ScanDir(cmd.Context(), agent, dir)
				if err != nil {
					return err
				}
				all = append(all, rep.Sessions...)
				scanned += rep.Scanned
				failures += len(rep.Errs)
				for _, e := range rep.Errs {
					fmt.Fprintf(os.Stderr, "vedei: %v\n", e)
				}
			}

			if asJSON {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				if err := enc.Encode(all); err != nil {
					return err
				}
			} else {
				printSessions(all, scanned)
			}

			total := 0
			for _, s := range all {
				total += len(s.Findings)
			}
			if total > 0 {
				return findingsError{n: total}
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&path, "path", "", "audit this directory instead of the default agent locations")
	cmd.Flags().BoolVar(&asJSON, "json", false, "emit JSON instead of a table")
	return cmd
}

func printSessions(sessions []transcript.Session, scanned int) {
	if len(sessions) == 0 {
		fmt.Printf("%d transcript(s) scanned, nothing sensitive found\n", scanned)
		return
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "TYPE\tVALUE\tCONFIDENCE\tOCCURRENCES\tTRANSCRIPT")
	total := 0
	for _, s := range sessions {
		for _, f := range s.Findings {
			_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%s\n",
				f.Type, truncate(f.Redacted, 28), f.Confidence, len(f.Locations), shorten(s.Path))
			total++
		}
	}
	_ = w.Flush()

	fmt.Printf("\n%d finding(s) across %d of %d transcript(s), last modified %s\n",
		total, len(sessions), scanned, sessions[0].Modified.Format("2006-01-02 15:04"))
	fmt.Println("These files are plaintext and unencrypted. Anyone who reads the disk reads them.")
}

// truncate keeps a redacted value from stretching the whole table. The value
// is already masked, so the tail is all a reader needs to match it against
// what they expected.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return "..." + s[len(s)-n+3:]
}

func shorten(path string) string {
	if home, err := os.UserHomeDir(); err == nil && len(path) > len(home) && path[:len(home)] == home {
		return "~" + path[len(home):]
	}
	return path
}
