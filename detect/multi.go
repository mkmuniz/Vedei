package detect

import (
	"context"
	"errors"
	"sort"
)

// Multi runs several engines over the same content and merges their findings.
//
// It is the piece that lets a caller treat "Brazilian personal data" and
// "leaked credentials" as one question, while each engine keeps its own
// validation model.
type Multi struct {
	engines []Engine
}

// NewMulti returns a Multi over the given engines, in the order supplied.
func NewMulti(engines ...Engine) *Multi { return &Multi{engines: engines} }

// Name implements Engine.
func (m *Multi) Name() string { return "multi" }

// Capabilities implements Engine by reporting the most demanding requirement
// of any member: if one engine needs the network, the set does, and the
// latency budget is the sum rather than the best case.
//
// A caller on the hot path can therefore ask one question — "may I run
// this?" — instead of inspecting every engine itself.
func (m *Multi) Capabilities() Capabilities {
	out := Capabilities{Deterministic: true}
	for _, e := range m.engines {
		c := e.Capabilities()
		out.RequiresNetwork = out.RequiresNetwork || c.RequiresNetwork
		out.Deterministic = out.Deterministic && c.Deterministic
		out.TypicalLatency += c.TypicalLatency
	}
	return out
}

// OfflineOnly returns a Multi holding only the engines that make no network
// calls, for use on paths where a request would be unacceptable — the agent
// hook and logging middleware.
func (m *Multi) OfflineOnly() *Multi {
	var kept []Engine
	for _, e := range m.engines {
		if !e.Capabilities().RequiresNetwork {
			kept = append(kept, e)
		}
	}
	return NewMulti(kept...)
}

// Scan runs every engine and returns the merged findings, ordered by first
// location so output is stable across runs.
//
// An engine that fails does not discard what the others found: the findings
// come back alongside the error, and the caller decides. On a reporting path
// that error must fail the scan rather than be swallowed — reporting "clean"
// when part of the scan broke is worse than a red build (ADR-005).
func (m *Multi) Scan(ctx context.Context, content []byte, meta Metadata) ([]Finding, error) {
	var (
		out  []Finding
		errs []error
	)

	for _, e := range m.engines {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		found, err := e.Scan(ctx, content, meta)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		out = append(out, found...)
	}

	out = dedupe(out)
	sort.SliceStable(out, func(i, j int) bool {
		li, lj := firstLocation(out[i]), firstLocation(out[j])
		if li.Line != lj.Line {
			return li.Line < lj.Line
		}
		if li.Column != lj.Column {
			return li.Column < lj.Column
		}
		return out[i].Fingerprint < out[j].Fingerprint
	})

	return out, errors.Join(errs...)
}

// dedupe merges findings that two engines reported for the same value. It can
// happen: a Pix key that is a CPF may also match a generic rule upstream.
// The first engine to report wins, because engines are supplied in order of
// specificity.
func dedupe(in []Finding) []Finding {
	seen := make(map[string]int, len(in))
	out := make([]Finding, 0, len(in))

	for _, f := range in {
		if i, ok := seen[f.Fingerprint]; ok {
			out[i].Locations = append(out[i].Locations, f.Locations...)
			continue
		}
		seen[f.Fingerprint] = len(out)
		out = append(out, f)
	}
	return out
}

func firstLocation(f Finding) Location {
	if len(f.Locations) == 0 {
		return Location{}
	}
	return f.Locations[0]
}

// Ensure Multi is itself an Engine, so it can be nested.
var _ Engine = (*Multi)(nil)
