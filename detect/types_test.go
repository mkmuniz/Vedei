package detect

import (
	"encoding/json"
	"strings"
	"testing"
)

// The single most important test in the package: ADR-003 says a detected
// value never leaves the process, and JSON is the main way things leave.
func TestFinding_RawIsNeverSerialized(t *testing.T) {
	const secret = "529.982.247-25"

	f := Finding{
		Type:     "cpf",
		Engine:   "br",
		Redacted: "***.***.**7-25",
		Raw:      secret,
		Validity: ValidityStructural,
		Extra:    map[string]string{"brand": "none"},
	}

	b, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(b), secret) {
		t.Fatalf("raw value leaked into JSON: %s", b)
	}

	// Also check a slice, which is what reporters actually emit.
	b, err = json.Marshal([]Finding{f, f})
	if err != nil {
		t.Fatalf("marshal slice: %v", err)
	}
	if strings.Contains(string(b), secret) {
		t.Fatalf("raw value leaked from slice: %s", b)
	}
}

// A struct field added later without a json:"-" tag would silently defeat the
// test above, so assert on the shape of the serialized object instead of
// trusting that nobody adds a field.
func TestFinding_SerializedKeysAreExpected(t *testing.T) {
	b, err := json.Marshal(Finding{})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	allowed := map[string]bool{
		"type": true, "engine": true, "value": true, "validity": true,
		"confidence": true, "severity": true, "reason": true,
		"fingerprint": true, "locations": true, "extra": true,
	}
	for k := range m {
		if !allowed[k] {
			t.Errorf("unexpected key %q in serialized Finding; if it can hold a "+
				"detected value it must be tagged json:\"-\"", k)
		}
	}
}

func TestValidity_InvalidIsDistinctFromUnknown(t *testing.T) {
	// Conflating them would let a failed check digit be reported as
	// "could not check", which is the opposite of what it means.
	if ValidityInvalid == ValidityUnknown {
		t.Fatal("ValidityInvalid and ValidityUnknown must differ")
	}
}
