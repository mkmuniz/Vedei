package br

import (
	"context"
	"time"

	"github.com/mkmuniz/nadzor/detect"
	brdetect "github.com/mkmuniz/nadzor/detect/br"
	"github.com/mkmuniz/nadzor/fingerprint"
	"github.com/mkmuniz/nadzor/redact"
)

// Engine detects Brazilian sensitive data. It makes no network calls, which
// is what allows it on the hot path.
type Engine struct{}

// New returns the Brazilian data engine.
func New() *Engine { return &Engine{} }

// Name implements detect.Engine.
func (e *Engine) Name() string { return "br" }

// Capabilities implements detect.Engine. The zero network requirement is the
// whole point: validation here is arithmetic, not a request.
func (e *Engine) Capabilities() detect.Capabilities {
	return detect.Capabilities{
		RequiresNetwork: false,
		TypicalLatency:  time.Microsecond,
		Deterministic:   true,
	}
}

// Scan implements detect.Engine.
//
// Every match returned by the extractor has already passed its validator, so
// findings leave with ValidityStructural. A candidate that failed its check
// digit never reaches this point.
func (e *Engine) Scan(_ context.Context, content []byte, meta detect.Metadata) ([]detect.Finding, error) {
	s := string(content)

	matches := brdetect.Extract(s)
	matches = append(matches, brdetect.ExtractPixKeys(s)...)
	if len(matches) == 0 {
		return nil, nil
	}

	// One value seen in several places is one finding with several locations,
	// not several findings.
	byPrint := make(map[string]*detect.Finding, len(matches))
	order := make([]string, 0, len(matches))

	for _, m := range matches {
		kind := string(m.Kind)
		fp := fingerprint.Of(kind, m.Value)

		if f, ok := byPrint[fp]; ok {
			f.Locations = append(f.Locations, locationOf(s, m.Start, m.End))
			continue
		}

		f := &detect.Finding{
			Type:        kind,
			Engine:      e.Name(),
			Redacted:    redact.Mask(m.Value),
			Raw:         m.Value,
			Validity:    detect.ValidityStructural,
			Confidence:  confidenceFor(m.Kind),
			Reason:      reasonFor(m.Kind),
			Fingerprint: fp,
			Locations:   []detect.Location{locationOf(s, m.Start, m.End)},
		}
		if m.Kind == brdetect.KindPAN {
			f.Extra = map[string]string{"brand": string(brdetect.DetectCardBrand(m.Value))}
		}
		if m.Kind == brdetect.KindPixKey {
			t, _ := brdetect.ClassifyPixKey(m.Value)
			f.Extra = map[string]string{"pix_key_type": string(t)}
		}
		if meta.Path != "" {
			f.Locations[0].Path = meta.Path
		}

		byPrint[fp] = f
		order = append(order, fp)
	}

	out := make([]detect.Finding, 0, len(order))
	for _, fp := range order {
		out = append(out, *byPrint[fp])
	}
	return out, nil
}

// confidenceFor reflects how much the check digit actually proves.
//
// CNS is medium rather than high because its checksum leaves position five
// unprotected, so a typo there still validates. CNH is medium because an
// eleven-digit run is a common shape and the algorithm is weaker than CPF's.
func confidenceFor(k brdetect.Kind) detect.Confidence {
	switch k {
	case brdetect.KindCPF, brdetect.KindCNPJ, brdetect.KindPAN, brdetect.KindPixKey:
		return detect.ConfidenceHigh
	case brdetect.KindCNS, brdetect.KindCNH:
		return detect.ConfidenceMedium
	default:
		return detect.ConfidenceMedium
	}
}

func reasonFor(k brdetect.Kind) string {
	switch k {
	case brdetect.KindPAN:
		return "luhn checksum ok"
	case brdetect.KindPixKey:
		return "well-formed Pix key"
	case brdetect.KindCNS:
		return "mod 11 ok; position five is unprotected by the scheme"
	default:
		return "check digit ok"
	}
}

// locationOf converts a byte offset into a 1-based line and column.
func locationOf(s string, start, end int) detect.Location {
	line, col := 1, 1
	for i := 0; i < start && i < len(s); i++ {
		if s[i] == '\n' {
			line++
			col = 1
		} else {
			col++
		}
	}
	return detect.Location{
		Line:      line,
		Column:    col,
		ByteStart: start,
		ByteEnd:   end,
	}
}
