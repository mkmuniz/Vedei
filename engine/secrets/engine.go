package secrets

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	bldetect "github.com/betterleaks/betterleaks/detect"
	bllogging "github.com/betterleaks/betterleaks/logging"
	blreport "github.com/betterleaks/betterleaks/report"
	"github.com/rs/zerolog"

	"github.com/mkmuniz/vedei/detect"
	"github.com/mkmuniz/vedei/detect/aws"
	"github.com/mkmuniz/vedei/fingerprint"
	"github.com/mkmuniz/vedei/redact"
)

// Engine detects leaked credentials by wrapping betterleaks.
//
// vedei writes no secret rules of its own. Maintaining a competing corpus
// would take years and still lag; betterleaks is MIT and already carries
// hundreds of validated rules (ADR-001). This adapter is the only place in
// the codebase that imports it, so when its v2 API lands — the module path
// becomes /v2 and Detector splits into Scanner and Analyzer — nothing
// outside this file changes.
type Engine struct {
	once     sync.Once
	detector *bldetect.Detector
	initErr  error
}

// New returns the secret engine. The underlying rule set is compiled lazily
// on first use, because loading several hundred rules costs tens of
// milliseconds and a caller that never scans should not pay it.
func New() *Engine { return &Engine{} }

// Name implements detect.Engine.
func (e *Engine) Name() string { return "secrets" }

// Capabilities implements detect.Engine.
//
// RequiresNetwork is false because live validation is not enabled here: that
// arrives in M9, together with the destination allowlist that betterleaks
// itself lacks. Until then this engine is as offline as the Brazilian one.
func (e *Engine) Capabilities() detect.Capabilities {
	return detect.Capabilities{
		RequiresNetwork: false,
		TypicalLatency:  time.Millisecond,
		Deterministic:   true,
	}
}

// RuleCount returns how many rules the compiled rule set holds. It exists so
// a test can fail if an upgrade silently empties the corpus.
func (e *Engine) RuleCount() (int, error) {
	if err := e.init(); err != nil {
		return 0, err
	}
	return len(e.detector.Config.Rules), nil
}

// silenceUpstreamLogger disables betterleaks' package-level logger.
//
// It attaches the detected secret as a log field in five places, for example
//
//	logger := logging.With().Str("finding", finding.Secret).Logger()
//
// Every one of those emits at Debug and its default level is Info, so
// nothing leaks today. That is a default, not a guarantee: logging.Logger is
// an exported package variable, so any dependency, any future version, or
// anyone debugging can raise the level and start writing credentials to
// stderr.
//
// ADR-003 says a detected value never leaves the process. Relying on someone
// else's default level is not a way to keep that promise, so the logger is
// disabled outright. vedei does not use its output for anything.
func silenceUpstreamLogger() {
	bllogging.Logger = zerolog.Nop()
}

func (e *Engine) init() error {
	e.once.Do(func() {
		silenceUpstreamLogger()

		d, err := bldetect.NewDetectorDefaultConfig()
		if err != nil {
			e.initErr = fmt.Errorf("loading betterleaks rules: %w", err)
			return
		}
		e.detector = d
	})
	return e.initErr
}

// Scan implements detect.Engine.
func (e *Engine) Scan(ctx context.Context, content []byte, meta detect.Metadata) ([]detect.Finding, error) {
	if err := e.init(); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(content) == 0 {
		return nil, nil
	}

	text := string(content)
	raw := e.detector.DetectString(text)

	// A second pass over the same text with Portuguese and Spanish key names
	// translated, so a credential in "senha" or "segredo" meets the same rules
	// and filters as one in "password" or "secret". Values are never rewritten,
	// so locationsOf below finds every secret from this pass in the original
	// text, and a value both passes report collapses into one finding by
	// fingerprint. See localize.go for the measurement behind it.
	if localized, ok := localizeKeys(text); ok {
		raw = append(raw, e.detector.DetectString(localized)...)
	}

	// One credential found in several places is one finding with several
	// locations, matching how the Brazilian engine reports.
	byPrint := make(map[string]*detect.Finding, len(raw))
	order := make([]string, 0, len(raw))
	for _, f := range raw {
		if f.Secret == "" {
			continue
		}
		fp := fingerprint.Of(f.RuleID, f.Secret)
		locs := locationsOf(text, f.Secret, meta.Path)
		if len(locs) == 0 {
			// The rule reported a secret that is not a substring of the input.
			// Nothing can be redacted, and a finding whose value cannot be
			// pointed at would report a leak the caller cannot act on.
			continue
		}

		if _, seen := byPrint[fp]; seen {
			// locationsOf already recorded every occurrence of this value, so
			// a second rule hit on the same credential adds nothing.
			continue
		}

		byPrint[fp] = &detect.Finding{
			Type:        f.RuleID,
			Engine:      e.Name(),
			Redacted:    redact.Mask(f.Secret),
			Raw:         f.Secret,
			Validity:    validityOf(f.ValidationStatus),
			Confidence:  confidenceOf(f),
			Reason:      reasonOf(f),
			Fingerprint: fp,
			Locations:   locs,
			Extra:       extraOf(f),
		}
		order = append(order, fp)
	}

	// The one rule vedei owns. betterleaks reports no AWS access key id at all —
	// measured, not assumed — so this runs alongside it rather than relying on
	// it. ADR-001 keeps betterleaks the only *imported* corpus; this is a
	// deliberate, documented exception for a gap that corpus/cases proves.
	addAWSFindings(text, meta, byPrint, &order)

	out := make([]detect.Finding, 0, len(order))
	for _, fp := range order {
		out = append(out, *byPrint[fp])
	}
	return out, nil
}

// addAWSFindings appends vedei's own AWS detections to the finding set, keyed
// the same way as betterleaks' so a value seen twice stays one finding.
//
// An access key id is structural, like a CPF whose check digits close: the shape
// and the base32 alphabet prove it is well-formed, not that it still works. It
// is reported High confidence because the prefix-plus-base32 combination is
// specific — a random 20-character token almost never lands on it — and Unknown
// validity, because confirming a live key means calling AWS, which is M9.
func addAWSFindings(text string, meta detect.Metadata, byPrint map[string]*detect.Finding, order *[]string) {
	for _, m := range aws.Extract(text) {
		fp := fingerprint.Of(aws.AccessKeyID, m.Value)
		if existing, seen := byPrint[fp]; seen {
			existing.Locations = append(existing.Locations, locationOf(text, m.Start, m.End, meta.Path))
			continue
		}
		byPrint[fp] = &detect.Finding{
			Type:        aws.AccessKeyID,
			Engine:      "secrets",
			Redacted:    redact.Mask(m.Value),
			Raw:         m.Value,
			Validity:    detect.ValidityUnknown,
			Confidence:  detect.ConfidenceHigh,
			Reason:      "AWS access key id: known prefix and base32 body",
			Fingerprint: fp,
			Locations:   []detect.Location{locationOf(text, m.Start, m.End, meta.Path)},
		}
		*order = append(*order, fp)
	}
}

// locationsOf returns every byte range in text holding secret.
//
// betterleaks reports a line and a column, not a byte offset, and the
// redaction path needs offsets: without them stream.Processor has nothing to
// replace, so a secret was reported on stderr and still handed to the model.
// That was the bug this function exists to close — the whole promise of the
// tool, silently broken for every credential.
//
// Every occurrence is recorded, not only the reported one. Redaction that
// leaves the second copy of a key in place has not redacted it.
func locationsOf(text, secret, path string) []detect.Location {
	if secret == "" {
		return nil
	}
	var out []detect.Location
	for from := 0; from < len(text); {
		i := strings.Index(text[from:], secret)
		if i < 0 {
			break
		}
		start := from + i
		end := start + len(secret)
		out = append(out, locationOf(text, start, end, path))
		from = end
	}
	return out
}

// locationOf builds a Location, counting the line and column up to start so a
// report can name a place a person recognizes.
func locationOf(text string, start, end int, path string) detect.Location {
	line, col := 1, 1
	for i := 0; i < start && i < len(text); i++ {
		if text[i] == '\n' {
			line++
			col = 1
		} else {
			col++
		}
	}
	return detect.Location{
		Path:      path,
		Line:      line,
		Column:    col,
		ByteStart: start,
		ByteEnd:   end,
	}
}

// validityOf maps betterleaks' validation status onto vedei's vocabulary.
//
// A secret that was never checked against its provider is Unknown, not
// Structural: unlike a CPF, there is no arithmetic that proves a credential
// is well formed. A regex matching is evidence of shape, not of validity,
// and conflating the two would overstate what vedei knows.
func validityOf(s blreport.ValidationStatus) detect.Validity {
	switch strings.ToLower(string(s)) {
	case "valid":
		return detect.ValidityLive
	case "invalid", "revoked":
		return detect.ValidityRevoked
	default:
		return detect.ValidityUnknown
	}
}

func confidenceOf(f blreport.Finding) detect.Confidence {
	switch strings.ToLower(f.Attributes["confidence"]) {
	case "high":
		return detect.ConfidenceHigh
	case "low":
		return detect.ConfidenceLow
	default:
		return detect.ConfidenceMedium
	}
}

func reasonOf(f blreport.Finding) string {
	if f.ValidationReason != "" {
		return f.ValidationReason
	}
	if f.Description != "" {
		return f.Description
	}
	return "matched rule " + f.RuleID
}

// extraOf carries across the metadata worth keeping, and nothing that could
// hold the secret. MatchContext and Line are deliberately excluded: both can
// contain the credential verbatim, and nothing in vedei may carry it into a
// report (ADR-003).
func extraOf(f blreport.Finding) map[string]string {
	extra := map[string]string{}
	if f.Entropy > 0 {
		extra["entropy"] = fmt.Sprintf("%.2f", f.Entropy)
	}
	for _, k := range []string{"git.sha", "git.author_email", "commit"} {
		if v, ok := f.Attributes[k]; ok && v != "" {
			extra[k] = v
		}
	}
	if len(extra) == 0 {
		return nil
	}
	return extra
}
