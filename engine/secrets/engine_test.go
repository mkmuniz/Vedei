package secrets

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	bllogging "github.com/betterleaks/betterleaks/logging"
	"github.com/rs/zerolog"

	"github.com/mkmuniz/nadzor/detect"
)

// stripeKey is assembled at run time rather than written as a literal.
// A Stripe-shaped key committed to this repository is caught by GitHub push
// protection — correctly, since neither its scanner nor ours can tell a test
// fixture from a live credential by looking at it. Building it here keeps the
// test honest without putting the pattern in the tree.
var stripeKey = "sk" + "_live_" + "4eC39HqLyjWDarjtT1zdp7dc"

func scan(t *testing.T, text string) []detect.Finding {
	t.Helper()
	fs, err := New().Scan(context.Background(), []byte(text), detect.Metadata{Path: "cfg.go"})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	return fs
}

// The reason this engine exists: hundreds of rules for free. If an upgrade
// empties the corpus, this fails instead of the tool silently finding nothing.
func TestRuleCount_CorpusIsLoaded(t *testing.T) {
	n, err := New().RuleCount()
	if err != nil {
		t.Fatalf("RuleCount: %v", err)
	}
	if n < 300 {
		t.Fatalf("only %d rules loaded; the betterleaks corpus looks broken", n)
	}
	t.Logf("%d rules inherited from betterleaks", n)
}

func TestScan_FindsAKnownSecret(t *testing.T) {
	fs := scan(t, `stripe = "`+stripeKey+`"`)
	if len(fs) == 0 {
		t.Fatal("no finding for a live-format Stripe key")
	}
	f := fs[0]
	if f.Engine != "secrets" {
		t.Errorf("engine = %s", f.Engine)
	}
	if f.Type == "" || f.Fingerprint == "" {
		t.Errorf("finding is missing type or fingerprint: %+v", f)
	}
	if f.Locations[0].Path != "cfg.go" {
		t.Errorf("path not carried through: %+v", f.Locations[0])
	}
}

// ADR-003 at this engine's boundary. betterleaks findings carry the secret in
// several fields; the adapter must not let any of them reach a report.
func TestScan_JSONNeverLeaksTheSecret(t *testing.T) {
	b, err := json.Marshal(scan(t, `stripe = "`+stripeKey+`"`))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(b), stripeKey) {
		t.Fatalf("secret leaked into JSON: %s", b)
	}
	// The match context and raw line are the usual culprits.
	if strings.Contains(string(b), stripeKey[:13]) {
		t.Fatalf("a fragment of the secret leaked: %s", b)
	}
}

func TestScan_RedactedHidesTheSecret(t *testing.T) {
	for _, f := range scan(t, `stripe = "`+stripeKey+`"`) {
		if f.Redacted == f.Raw {
			t.Error("Redacted must differ from Raw")
		}
		if strings.Contains(f.Redacted, stripeKey[8:13]) {
			t.Errorf("secret body survived redaction: %s", f.Redacted)
		}
	}
}

// An unvalidated secret is Unknown, not Structural. A regex matching proves
// shape; only the provider proves the credential works.
func TestScan_UnvalidatedSecretIsUnknown(t *testing.T) {
	for _, f := range scan(t, `stripe = "`+stripeKey+`"`) {
		if f.Validity != detect.ValidityUnknown {
			t.Errorf("validity = %s, want unknown for an unvalidated secret", f.Validity)
		}
	}
}

func TestScan_PlainTextYieldsNothing(t *testing.T) {
	if fs := scan(t, "esta linha nao tem segredo nenhum"); len(fs) != 0 {
		t.Errorf("unexpected findings: %+v", fs)
	}
}

func TestScan_EmptyInput(t *testing.T) {
	if fs := scan(t, ""); len(fs) != 0 {
		t.Errorf("empty input produced findings: %+v", fs)
	}
}

func TestScan_DeduplicatesByValue(t *testing.T) {
	text := `a = "` + stripeKey + `"` + "\n" + `b = "` + stripeKey + `"`
	fs := scan(t, text)
	if len(fs) != 1 {
		t.Fatalf("want 1 deduplicated finding, got %d", len(fs))
	}
	if len(fs[0].Locations) != 2 {
		t.Errorf("want 2 locations, got %d", len(fs[0].Locations))
	}
}

func TestScan_RespectsContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := New().Scan(ctx, []byte(`x = "`+stripeKey+`"`), detect.Metadata{}); err == nil {
		t.Error("a cancelled context should stop the scan")
	}
}

func TestCapabilities_OfflineUntilM9(t *testing.T) {
	c := New().Capabilities()
	if c.RequiresNetwork {
		t.Fatal("live validation is not enabled yet; this engine must stay offline")
	}
}

var _ detect.Engine = (*Engine)(nil)

// betterleaks attaches the detected secret as a log field in five places.
// Those all emit at Debug and its default level is Info, so nothing leaks
// today — but logging.Logger is an exported package variable, and ADR-003
// cannot rest on someone else's default. This test raises the level to Trace
// and captures stderr: if the adapter ever stops disabling that logger, the
// secret appears here and the build fails.
func TestScan_UpstreamLoggerCannotEmitTheSecret(t *testing.T) {
	var captured bytes.Buffer
	bllogging.Logger = zerolog.New(&captured).Level(zerolog.TraceLevel)

	e := New()
	if _, err := e.Scan(context.Background(), []byte(`k = "`+stripeKey+`"`), detect.Metadata{}); err != nil {
		t.Fatalf("scan: %v", err)
	}

	if strings.Contains(captured.String(), stripeKey) {
		t.Fatalf("the secret reached the upstream log: %s", captured.String())
	}
	if captured.Len() != 0 {
		t.Errorf("upstream logger should be silent, wrote: %s", captured.String())
	}
}

// A finding without byte offsets is a finding stream.Processor cannot act on,
// which is how every secret reached the model while stderr claimed it had been
// redacted. The offsets are load-bearing, so they are asserted directly.
func TestScan_FindingsCarryByteOffsets(t *testing.T) {
	text := `key = "` + stripeKey + `"`
	fs := scan(t, text)
	if len(fs) == 0 {
		t.Fatal("no findings")
	}

	for _, f := range fs {
		if len(f.Locations) == 0 {
			t.Fatalf("%s has no locations", f.Type)
		}
		for _, loc := range f.Locations {
			if loc.ByteEnd <= loc.ByteStart {
				t.Errorf("%s: empty range %d..%d", f.Type, loc.ByteStart, loc.ByteEnd)
				continue
			}
			if loc.ByteEnd > len(text) {
				t.Errorf("%s: range %d..%d is past the end of a %d byte input",
					f.Type, loc.ByteStart, loc.ByteEnd, len(text))
				continue
			}
			// The range has to cover the value itself, or replacing it would
			// mask the wrong bytes.
			if got := text[loc.ByteStart:loc.ByteEnd]; got != stripeKey {
				t.Errorf("%s: range covers %q, not the secret", f.Type, got)
			}
		}
	}
}

// Every occurrence has to be covered: leaving the second copy in place is not
// a redaction.
func TestScan_LocatesEveryOccurrence(t *testing.T) {
	text := `a = "` + stripeKey + `"` + "\n" + `b = "` + stripeKey + `"`
	fs := scan(t, text)
	if len(fs) != 1 {
		t.Fatalf("want 1 finding, got %d", len(fs))
	}
	if n := len(fs[0].Locations); n != 2 {
		t.Fatalf("want 2 locations, got %d", n)
	}
	if l := fs[0].Locations[1].Line; l != 2 {
		t.Errorf("the second occurrence is on line %d, want 2", l)
	}
}
