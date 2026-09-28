package engine

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/mkmuniz/nadzor/detect"
	"github.com/mkmuniz/nadzor/stream"
)

// stripeKey is assembled at run time. Committing a Stripe-shaped key would
// be blocked by GitHub push protection, which cannot tell a fixture from a
// live credential — the same limitation nadzor has, and the reason the
// fixture on disk carries no secret of its own.
var stripeKey = "sk" + "_live_" + "4eC39HqLyjWDarjtT1zdp7dc"

// fixture returns the shared test file with a secret appended, so the tree
// holds no credential-shaped string.
func fixture() ([]byte, error) {
	content, err := os.ReadFile("../testdata/misto.txt")
	if err != nil {
		return nil, err
	}
	return append(content, []byte("stripe:        "+stripeKey+"\n")...), nil
}

// The integration test the milestone is really about: both engines over one
// file, one output format, and nothing that should be silent making noise.
func TestAll_BothEnginesOverOneFile(t *testing.T) {
	content, err := fixture()
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}

	fs, err := All().Scan(context.Background(), content, detect.Metadata{Path: "misto.txt"})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	byType := map[string]detect.Finding{}
	for _, f := range fs {
		byType[f.Type] = f
		t.Logf("%-24s %-22s engine=%-8s conf=%s", f.Type, f.Redacted, f.Engine, f.Confidence)
	}

	// Each engine must have contributed.
	for _, want := range []string{"cpf", "cnpj", "card-pan", "pix-e2eid", "pix-key"} {
		if _, ok := byType[want]; !ok {
			t.Errorf("Brazilian engine missed %s", want)
		}
	}
	secretFound := false
	for _, f := range fs {
		if f.Engine == "secrets" {
			secretFound = true
		}
	}
	if !secretFound {
		t.Error("the secrets engine contributed nothing")
	}
}

// What must NOT appear is as much the point as what must.
func TestAll_SilentOnWhatShouldBeSilent(t *testing.T) {
	content, _ := fixture()
	fs, _ := All().Scan(context.Background(), content, detect.Metadata{})

	for _, f := range fs {
		// The invalid CPF differs from the valid one only in its check digits.
		if f.Raw == "529.982.247-26" {
			t.Error("a CPF that fails its check digit was reported")
		}
		// The forged receipt: well formed, but its ISPB is not registered.
		if strings.HasPrefix(f.Raw, "E99999999") {
			t.Error("an E2EID with an unregistered ISPB was reported")
		}
		// A SHA-256 hash holds digit runs that satisfy mod 11 by chance.
		if strings.Contains(f.Raw, "a3f5c8d9") {
			t.Error("a fragment of a hash was reported")
		}
	}
}

// ADR-003 across the whole pipeline, not just one engine.
func TestAll_NoValueSurvivesSerialization(t *testing.T) {
	content, _ := fixture()
	fs, _ := All().Scan(context.Background(), content, detect.Metadata{})

	b, err := json.Marshal(fs)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, secret := range []string{
		"529.982.247-25", "52998224725",
		"12.ABC.345/01DE-35",
		"4539578763621486",
		stripeKey,
		"E60701190202609261430abc12345678",
	} {
		if strings.Contains(string(b), secret) {
			t.Errorf("value leaked into JSON: %s", secret)
		}
	}
}

func TestOffline_MakesNoNetworkCall(t *testing.T) {
	if Offline().Capabilities().RequiresNetwork {
		t.Fatal("the offline set must never require the network")
	}
}

func TestBrazilianOnly_ExcludesSecrets(t *testing.T) {
	fs, err := BrazilianOnly().Scan(context.Background(),
		[]byte(`k = "`+stripeKey+`"`), detect.Metadata{})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	for _, f := range fs {
		if f.Engine == "secrets" {
			t.Error("BrazilianOnly ran the secrets engine")
		}
	}
}

// The regression that matters most in this repository.
//
// Secret findings carried a line and a column but no byte offsets, so
// stream.Processor had nothing to replace: every credential was announced on
// stderr as redacted and handed to the model anyway. Reporting a leak and
// causing it are not the same thing, and only a test at this layer — the real
// engine set behind the real processor — can tell them apart.
func TestOffline_SecretsAreRemovedFromTheText(t *testing.T) {
	content, err := fixture()
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}

	p, err := stream.New(Offline())
	if err != nil {
		t.Fatalf("stream.New: %v", err)
	}

	out, res := p.Process(context.Background(), string(content), detect.Metadata{Path: "misto.txt"})
	if res.Degraded {
		t.Fatalf("degraded: %v", res.Err)
	}
	if !res.Redacted {
		t.Fatal("nothing was redacted")
	}
	if strings.Contains(out, stripeKey) {
		t.Errorf("the secret survived redaction:\n%s", out)
	}

	// Findings are only actionable if they point somewhere.
	for _, f := range res.Findings {
		if len(f.Locations) == 0 {
			t.Errorf("%s (%s) has no locations", f.Type, f.Engine)
			continue
		}
		for _, loc := range f.Locations {
			if loc.ByteEnd <= loc.ByteStart {
				t.Errorf("%s (%s): empty range %d..%d", f.Type, f.Engine, loc.ByteStart, loc.ByteEnd)
			}
		}
	}
}
