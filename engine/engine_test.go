package engine

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/mkmuniz/nadzor/detect"
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
	for _, want := range []string{"cpf", "cnpj", "card-pan", "pix-e2eid"} {
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
