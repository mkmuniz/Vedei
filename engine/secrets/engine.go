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

	"github.com/mkmuniz/nadzor/detect"
	"github.com/mkmuniz/nadzor/fingerprint"
	"github.com/mkmuniz/nadzor/redact"
)

// Engine detects leaked credentials by wrapping betterleaks.
//
// nadzor writes no secret rules of its own. Maintaining a competing corpus
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
// disabled outright. nadzor does not use its output for anything.
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

	raw := e.detector.DetectString(string(content))
	if len(raw) == 0 {
		return nil, nil
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
		loc := detect.Location{
			Path:   meta.Path,
			Line:   f.StartLine,
			Column: f.StartColumn,
		}

		if existing, ok := byPrint[fp]; ok {
			existing.Locations = append(existing.Locations, loc)
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
			Locations:   []detect.Location{loc},
			Extra:       extraOf(f),
		}
		order = append(order, fp)
	}

	out := make([]detect.Finding, 0, len(order))
	for _, fp := range order {
		out = append(out, *byPrint[fp])
	}
	return out, nil
}

// validityOf maps betterleaks' validation status onto nadzor's vocabulary.
//
// A secret that was never checked against its provider is Unknown, not
// Structural: unlike a CPF, there is no arithmetic that proves a credential
// is well formed. A regex matching is evidence of shape, not of validity,
// and conflating the two would overstate what nadzor knows.
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
// contain the credential verbatim, and nothing in nadzor may carry it into a
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
