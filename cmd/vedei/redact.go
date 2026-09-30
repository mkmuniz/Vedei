package main

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/mkmuniz/vedei/daemon"
	"github.com/mkmuniz/vedei/detect"
	"github.com/mkmuniz/vedei/engine"
	"github.com/mkmuniz/vedei/stream"
)

// redactOpts are the flags every redaction command shares.
type redactOpts struct {
	socket   string
	noDaemon bool
	fast     bool
	maxInput int
}

// bindRedactFlags registers the shared flags on cmd.
//
// The --fast flag is about startup cost, which the daemon has already paid, so
// it has no effect on a request the daemon serves.
func bindRedactFlags(cmd *cobra.Command, o *redactOpts, withFast bool) {
	cmd.Flags().StringVar(&o.socket, "socket", daemon.DefaultSocket(),
		"daemon socket to use when one is listening")
	cmd.Flags().BoolVar(&o.noDaemon, "no-daemon", false,
		"always scan in-process, even when a daemon is listening")
	if withFast {
		cmd.Flags().BoolVar(&o.fast, "fast", false,
			"skip the secret rule set, cutting startup at the cost of missing credentials (ignored when the daemon answers)")
	}
}

// redaction is the outcome of a redact call, whichever path served it.
type redaction struct {
	Text      string
	Findings  []detect.Finding
	Redacted  bool
	Degraded  bool
	Err       error
	ViaDaemon bool
}

// redact returns text with every detected value replaced.
//
// It prefers the daemon, which has the rules compiled already, and falls back
// to scanning in-process on any failure. The fallback is the whole point: a
// daemon that is down must cost a few milliseconds, not a broken session.
func redact(ctx context.Context, text string, meta detect.Metadata, o redactOpts) redaction {
	if !o.noDaemon && o.socket != "" {
		if r, ok := redactViaDaemon(ctx, text, meta, o.socket); ok {
			return r
		}
	}
	return redactInProcess(ctx, text, meta, o)
}

func redactViaDaemon(ctx context.Context, text string, meta detect.Metadata, socket string) (redaction, bool) {
	c, err := daemon.Dial(ctx, socket)
	if err != nil {
		return redaction{}, false
	}
	defer func() { _ = c.Close() }()

	resp, err := c.Redact(ctx, text, meta)
	if err != nil {
		return redaction{}, false
	}
	// A degraded answer means the daemon's engine failed, not that the daemon
	// is unreachable. Scanning again in-process would fail the same way.
	return redaction{
		Text:      resp.Text,
		Findings:  resp.Findings,
		Redacted:  resp.Redacted,
		Degraded:  resp.Degraded,
		Err:       errorOrNil(resp.Error),
		ViaDaemon: true,
	}, true
}

func redactInProcess(ctx context.Context, text string, meta detect.Metadata, o redactOpts) redaction {
	eng := engine.Offline()
	if o.fast {
		eng = engine.BrazilianOnly()
	}
	p, err := stream.New(eng, stream.WithMaxInput(o.maxInput))
	if err != nil {
		return redaction{Text: text, Degraded: true, Err: err}
	}

	out, res := p.Process(ctx, text, meta)
	return redaction{
		Text:     out,
		Findings: res.Findings,
		Redacted: res.Redacted,
		Degraded: res.Degraded,
		Err:      res.Err,
	}
}

func errorOrNil(s string) error {
	if s == "" {
		return nil
	}
	return fmt.Errorf("%s", s)
}
