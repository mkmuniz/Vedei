package stream

import (
	"context"
	"fmt"
	"io"
	"sort"

	"github.com/mkmuniz/nadzor/detect"
)

// Result reports what a Process call did.
type Result struct {
	// Findings is what was detected. Values are already redacted.
	Findings []detect.Finding
	// Redacted is true when the output differs from the input.
	Redacted bool
	// Degraded is true when the engine failed and the text was passed
	// through unmodified. Nothing was redacted; the caller was not blocked.
	Degraded bool
	// Err is the engine's error when Degraded is true. It is reported, not
	// returned, because on this path a failure must not stop the caller.
	Err error
}

// Annotator turns a finding into the text that replaces it. Supplying one is
// how a caller controls what the reader sees in place of the value.
type Annotator func(detect.Finding) string

// DefaultAnnotator replaces a value with its redacted form and a marker, so
// a reader — or a model — can tell something was removed rather than
// silently reading altered text.
func DefaultAnnotator(f detect.Finding) string {
	return fmt.Sprintf("%s [nadzor: %s redacted]", f.Redacted, f.Type)
}

// Processor redacts sensitive data out of text as it passes through.
//
// It is the hot path: an agent hook runs it on every tool result, so the
// budget is milliseconds, and an engine that would make a network call is
// refused outright rather than slowing the caller down.
type Processor struct {
	engine   detect.Engine
	annotate Annotator
	maxInput int
}

// Option configures a Processor.
type Option func(*Processor)

// WithAnnotator sets how a redacted value is rendered.
func WithAnnotator(a Annotator) Option {
	return func(p *Processor) { p.annotate = a }
}

// WithMaxInput caps how much text is scanned. Beyond the cap the text passes
// through unscanned rather than being held in memory, because on this path
// blocking the caller is worse than missing a redaction. Zero means no cap.
func WithMaxInput(n int) Option {
	return func(p *Processor) { p.maxInput = n }
}

// ErrRequiresNetwork is returned by New when the engine would make a request.
var ErrRequiresNetwork = fmt.Errorf("stream: engine requires the network and cannot run on this path")

// New returns a Processor over engine.
//
// An engine that requires the network is rejected rather than accepted and
// hoped about: this path runs inside someone else's latency budget, and a
// provider call there is not a slow scan, it is a broken session.
func New(engine detect.Engine, opts ...Option) (*Processor, error) {
	if engine.Capabilities().RequiresNetwork {
		return nil, ErrRequiresNetwork
	}
	p := &Processor{engine: engine, annotate: DefaultAnnotator}
	for _, o := range opts {
		o(p)
	}
	return p, nil
}

// Process returns text with every detected value replaced.
//
// It is fail-open by design (ADR-005): if the engine errors or panics, the
// original text is returned unchanged and the failure is reported in the
// Result. Breaking an agent session is worse than missing one redaction —
// the opposite of the reporting path, where a broken scan must fail loudly.
func (p *Processor) Process(ctx context.Context, text string, meta detect.Metadata) (out string, res Result) {
	defer func() {
		if r := recover(); r != nil {
			out = text
			res = Result{Degraded: true, Err: fmt.Errorf("stream: engine panicked: %v", r)}
		}
	}()

	if p.maxInput > 0 && len(text) > p.maxInput {
		return text, Result{Degraded: true,
			Err: fmt.Errorf("stream: input of %d bytes exceeds the %d byte cap", len(text), p.maxInput)}
	}

	findings, err := p.engine.Scan(ctx, []byte(text), meta)
	if err != nil {
		return text, Result{Degraded: true, Err: err}
	}
	if len(findings) == 0 {
		return text, Result{}
	}

	return p.replace(text, findings), Result{Findings: findings, Redacted: true}
}

// replace rewrites the text back to front, so an earlier replacement cannot
// shift the offsets of a later one.
func (p *Processor) replace(text string, findings []detect.Finding) string {
	type span struct {
		start, end int
		with       string
	}

	var spans []span
	for _, f := range findings {
		for _, loc := range f.Locations {
			if loc.ByteStart >= loc.ByteEnd || loc.ByteEnd > len(text) {
				continue
			}
			spans = append(spans, span{loc.ByteStart, loc.ByteEnd, p.annotate(f)})
		}
	}
	sort.Slice(spans, func(i, j int) bool { return spans[i].start > spans[j].start })

	out := []byte(text)
	prevStart := len(text)
	for _, s := range spans {
		if s.end > prevStart {
			continue // overlaps something already replaced
		}
		out = append(out[:s.start], append([]byte(s.with), out[s.end:]...)...)
		prevStart = s.start
	}
	return string(out)
}

// Copy streams from r to w, redacting as it goes, and returns what it found.
//
// The whole input is read before writing, because a value can straddle a
// read boundary and a partial match is worse than a slow one. WithMaxInput
// bounds the memory that costs.
func (p *Processor) Copy(ctx context.Context, w io.Writer, r io.Reader, meta detect.Metadata) (Result, error) {
	limit := int64(p.maxInput)
	reader := io.Reader(r)
	if limit > 0 {
		reader = io.LimitReader(r, limit+1)
	}

	content, err := io.ReadAll(reader)
	if err != nil {
		return Result{}, fmt.Errorf("stream: reading input: %w", err)
	}

	out, res := p.Process(ctx, string(content), meta)
	if _, err := io.WriteString(w, out); err != nil {
		return res, fmt.Errorf("stream: writing output: %w", err)
	}
	return res, nil
}
