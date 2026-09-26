package br

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/mkmuniz/nadzor/detect"
)

func scan(t *testing.T, text string) []detect.Finding {
	t.Helper()
	fs, err := New().Scan(context.Background(), []byte(text), detect.Metadata{Path: "x.go"})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	return fs
}

func TestScan_ReportsValidCPF(t *testing.T) {
	fs := scan(t, "cpf 529.982.247-25")
	if len(fs) != 1 {
		t.Fatalf("want 1 finding, got %d", len(fs))
	}
	f := fs[0]
	if f.Type != "cpf" || f.Engine != "br" {
		t.Errorf("unexpected type/engine: %s/%s", f.Type, f.Engine)
	}
	if f.Validity != detect.ValidityStructural {
		t.Errorf("validity = %s, want structural", f.Validity)
	}
	if f.Locations[0].Path != "x.go" || f.Locations[0].Line != 1 {
		t.Errorf("unexpected location: %+v", f.Locations[0])
	}
}

// An engine must never emit a finding that failed validation.
func TestScan_NeverReportsInvalid(t *testing.T) {
	for _, text := range []string{"cpf 529.982.247-26", "cnpj 11.222.333/0001-82"} {
		if fs := scan(t, text); len(fs) != 0 {
			t.Errorf("invalid value reported for %q: %+v", text, fs)
		}
	}
	for _, f := range scan(t, "cpf 529.982.247-25") {
		if f.Validity == detect.ValidityInvalid {
			t.Error("ValidityInvalid must never leave the engine")
		}
	}
}

// The same value in two places is one finding with two locations.
func TestScan_DeduplicatesByValue(t *testing.T) {
	fs := scan(t, "cpf 529.982.247-25\noutra linha 52998224725\n")
	if len(fs) != 1 {
		t.Fatalf("want 1 deduplicated finding, got %d", len(fs))
	}
	if len(fs[0].Locations) != 2 {
		t.Errorf("want 2 locations, got %d", len(fs[0].Locations))
	}
}

func TestScan_RedactedNeverContainsTheValue(t *testing.T) {
	const cpf = "529.982.247-25"
	for _, f := range scan(t, "cpf "+cpf) {
		if f.Redacted == cpf {
			t.Error("Redacted must not equal Raw")
		}
		if strings.Contains(f.Redacted, "529") {
			t.Errorf("identifying digits survived redaction: %s", f.Redacted)
		}
	}
}

// ADR-003 at the engine boundary, not just on the type.
func TestScan_JSONNeverLeaksTheValue(t *testing.T) {
	const cpf = "529.982.247-25"
	b, err := json.Marshal(scan(t, "cpf "+cpf))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(b), cpf) || strings.Contains(string(b), "52998224725") {
		t.Fatalf("value leaked into JSON: %s", b)
	}
}

func TestScan_CNSConfidenceIsMedium(t *testing.T) {
	// Its checksum leaves a digit unprotected, so it is weaker evidence.
	if confidenceFor("cns") != detect.ConfidenceMedium {
		t.Error("CNS should not be high confidence")
	}
}

func TestCapabilities_NoNetwork(t *testing.T) {
	c := New().Capabilities()
	if c.RequiresNetwork {
		t.Fatal("the br engine must never require the network (ADR-002)")
	}
	if !c.Deterministic {
		t.Error("the br engine must be deterministic")
	}
}

func TestScan_CardBrandIsReported(t *testing.T) {
	fs := scan(t, "cartao 4539578763621486")
	if len(fs) != 1 {
		t.Fatalf("want 1 finding, got %d", len(fs))
	}
	if fs[0].Extra["brand"] != "visa" {
		t.Errorf("brand = %q, want visa", fs[0].Extra["brand"])
	}
}

func TestScan_EmptyInput(t *testing.T) {
	if fs := scan(t, ""); len(fs) != 0 {
		t.Errorf("empty input produced findings: %+v", fs)
	}
}

// The engine must satisfy the interface it claims to.
var _ detect.Engine = (*Engine)(nil)
