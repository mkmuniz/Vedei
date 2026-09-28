package br

import (
	"context"
	"sort"
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

// dropOverlaps keeps one match per region of the text.
//
// Extract and ExtractPixKeys are separate passes, each with its own internal
// overlap guard, so neither sees the other's matches. A value both can claim —
// a phone number written as a Pix key, whose digits also satisfy Luhn — came
// back twice, at two types, over the same bytes.
//
// That has to be resolved here rather than downstream. The redaction path
// rewrites by byte offset and skips a span that overlaps one it already wrote,
// so an overlap silently discards whichever finding sorted second: the output
// is safe, but which of the two survived depends on sort order, and the report
// counts the same value twice.
//
// The longer match wins, because it is the one that saw the whole token: for
// "+5511980198775", the Pix key includes the country code and the card
// candidate is the fragment after it. Ties go to the earlier match, which keeps
// the result stable across runs.
func dropOverlaps(matches []brdetect.Match) []brdetect.Match {
	if len(matches) < 2 {
		return matches
	}

	order := make([]int, len(matches))
	for i := range order {
		order[i] = i
	}
	sort.SliceStable(order, func(a, b int) bool {
		x, y := matches[order[a]], matches[order[b]]
		if lx, ly := x.End-x.Start, y.End-y.Start; lx != ly {
			return lx > ly
		}
		return x.Start < y.Start
	})

	keep := make([]bool, len(matches))
	var taken []brdetect.Match
	for _, i := range order {
		m := matches[i]
		clash := false
		for _, t := range taken {
			if m.Start < t.End && t.Start < m.End {
				clash = true
				break
			}
		}
		if !clash {
			taken = append(taken, m)
			keep[i] = true
		}
	}

	out := matches[:0:0]
	for i, m := range matches {
		if keep[i] {
			out = append(out, m)
		}
	}
	return out
}

// Scan implements detect.Engine.
//
// Every match returned by the extractor has already passed its validator, so
// findings leave with ValidityStructural. A candidate that failed its check
// digit never reaches this point.
func (e *Engine) Scan(_ context.Context, content []byte, meta detect.Metadata) ([]detect.Finding, error) {
	s := string(content)

	matches := dropOverlaps(append(brdetect.Extract(s), brdetect.ExtractPixKeys(s)...))
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
		if m.Kind == brdetect.KindE2EID {
			if e2e, ok := brdetect.ParseE2EID(m.Value); ok {
				f.Extra = map[string]string{
					"ispb":        e2e.ISPB,
					"institution": e2e.Institution.Name,
					"timestamp":   e2e.Timestamp.Format("2006-01-02 15:04"),
				}
			}
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
	case brdetect.KindCPF, brdetect.KindCNPJ, brdetect.KindPAN,
		brdetect.KindPixKey, brdetect.KindE2EID:
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
	case brdetect.KindE2EID:
		return "well-formed Pix end-to-end id from a registered institution"
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
