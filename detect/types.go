package detect

import (
	"context"
	"time"
)

// Validity says how much is known about whether a finding is real.
//
// The distinction between Structural and Live is the heart of the project:
// personal data can only ever reach Structural, because confirming identity
// would mean querying an official registry, which nadzor does not do.
// See docs/adr/002-offline-validation.md.
type Validity string

const (
	// ValidityUnknown means the type carries no check digit, so nothing can
	// be computed. RG is the canonical example.
	ValidityUnknown Validity = "unknown"

	// ValidityInvalid means a check digit was computed and did not match.
	// Findings in this state never leave the engine.
	ValidityInvalid Validity = "invalid"

	// ValidityStructural means the value is well formed: its check digit
	// closes, its length is right, its embedded codes exist.
	ValidityStructural Validity = "structural"

	// ValidityLive means a provider confirmed the credential still works.
	// Only secrets reach this state, and only when validation is enabled.
	ValidityLive Validity = "live"

	// ValidityRevoked means a provider confirmed the credential no longer works.
	ValidityRevoked Validity = "revoked"
)

// Confidence is how likely the match is to be what the detector claims,
// independent of whether the value is well formed.
//
// A structurally valid CPF sitting in a file called fixtures.py is High on
// validity and Low on confidence: the number is real, the finding may not be.
type Confidence string

// The three confidence levels a finding can carry.
const (
	ConfidenceLow    Confidence = "low"
	ConfidenceMedium Confidence = "medium"
	ConfidenceHigh   Confidence = "high"
)

// Severity is how much damage the finding could cause. It is only meaningful
// once capability analysis exists (M7); until then it stays empty.
type Severity string

// The severity levels, assigned once capability analysis exists.
const (
	SeverityUnknown  Severity = ""
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// Location is where a finding was seen. A single value may occur in several
// places; Finding holds them all rather than being duplicated.
type Location struct {
	Path      string `json:"path,omitempty"`
	Line      int    `json:"line,omitempty"`
	Column    int    `json:"column,omitempty"`
	ByteStart int    `json:"byte_start,omitempty"`
	ByteEnd   int    `json:"byte_end,omitempty"`
}

// Metadata describes where the scanned content came from, without coupling
// the core to any particular source.
type Metadata struct {
	Path   string            `json:"path,omitempty"`
	Source string            `json:"source,omitempty"`
	Extra  map[string]string `json:"extra,omitempty"`
}

// Finding is one detected value. It is the single currency between engines,
// adapters and reporters.
//
// Raw carries the detected value and is deliberately excluded from every
// serialization. Redacted is what any output shows. Keeping them in separate
// fields, with the json tag doing the work, is what makes ADR-003 enforceable
// rather than aspirational.
type Finding struct {
	Type        string            `json:"type"`
	Engine      string            `json:"engine"`
	Redacted    string            `json:"value"`
	Raw         string            `json:"-"`
	Validity    Validity          `json:"validity"`
	Confidence  Confidence        `json:"confidence"`
	Severity    Severity          `json:"severity,omitempty"`
	Reason      string            `json:"reason,omitempty"`
	Fingerprint string            `json:"fingerprint"`
	Locations   []Location        `json:"locations,omitempty"`
	Extra       map[string]string `json:"extra,omitempty"`
}

// Capabilities declares what an engine needs in order to run, so a caller on
// a latency-bound path can refuse an engine that would make a network call.
type Capabilities struct {
	// RequiresNetwork is true when the engine may contact a third party.
	// An engine with this set must never run on the agent hook or in
	// logging middleware.
	RequiresNetwork bool

	// TypicalLatency is the expected cost of one Scan over a small input.
	TypicalLatency time.Duration

	// Deterministic is true when the same input always yields the same
	// findings. A network-validating engine is not deterministic.
	Deterministic bool
}

// Engine detects findings in content. Implementations must be safe for
// concurrent use and must not write to disk.
type Engine interface {
	// Name identifies the engine in Finding.Engine.
	Name() string

	// Scan returns the findings in content. It never returns a finding whose
	// Validity is ValidityInvalid.
	Scan(ctx context.Context, content []byte, meta Metadata) ([]Finding, error)

	// Capabilities declares what the engine needs to run.
	Capabilities() Capabilities
}
