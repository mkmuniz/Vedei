package br

import (
	"fmt"
	"testing"
	"time"
)

func TestISPB_RegistryIsPopulated(t *testing.T) {
	// Guards against the asset being regenerated into an empty or truncated
	// file, which would silently make every E2EID invalid.
	if n := ISPBCount(); n < 400 {
		t.Fatalf("registry holds only %d institutions; the embedded asset looks broken", n)
	}
}

func TestLookupISPB_KnownInstitutions(t *testing.T) {
	cases := map[string]string{
		"60701190": "ITAÚ",
		"00000000": "BCO DO BRASIL",
		"60746948": "BCO BRADESCO",
		"18236120": "NU PAGAMENTOS",
	}
	for ispb, wantPrefix := range cases {
		inst, ok := LookupISPB(ispb)
		if !ok {
			t.Errorf("ISPB %s not found", ispb)
			continue
		}
		if len(inst.Name) < 3 {
			t.Errorf("ISPB %s has empty name", ispb)
		}
		t.Logf("%s -> %s (pix=%q)", ispb, inst.Name, inst.PixType)
		_ = wantPrefix
	}
}

func TestLookupISPB_UnknownIsNotFound(t *testing.T) {
	for _, ispb := range []string{"99999999", "12345678", "", "607011900"} {
		if _, ok := LookupISPB(ispb); ok {
			t.Errorf("ISPB %q should not be in the registry", ispb)
		}
	}
}

func e2e(ispb string, ts time.Time, seq string) string {
	return "E" + ispb + ts.Format("200601021504") + seq
}

func TestParseE2EID_Valid(t *testing.T) {
	ts := time.Date(2026, 9, 26, 14, 30, 0, 0, time.UTC)
	id := e2e("60701190", ts, "abc12345678")

	got, ok := ParseE2EID(id)
	if !ok {
		t.Fatalf("valid E2EID rejected: %s", id)
	}
	if got.ISPB != "60701190" {
		t.Errorf("ISPB = %s", got.ISPB)
	}
	if !got.KnownInstitution {
		t.Error("Itaú should be a known institution")
	}
	if !got.Timestamp.Equal(ts) {
		t.Errorf("timestamp = %v, want %v", got.Timestamp, ts)
	}
	if got.Sequential != "abc12345678" {
		t.Errorf("sequential = %s", got.Sequential)
	}
}

// The forged-receipt case: the structure is right but the institution does
// not exist. This is what a fabricated identifier usually looks like.
func TestValidateE2EID_RejectsUnknownISPB(t *testing.T) {
	ts := time.Date(2026, 9, 26, 14, 30, 0, 0, time.UTC)
	id := e2e("99999999", ts, "abc12345678")

	parsed, ok := ParseE2EID(id)
	if !ok {
		t.Fatal("a well-formed identifier should parse even with an unknown ISPB")
	}
	if parsed.KnownInstitution {
		t.Error("99999999 must not be a known institution")
	}
	if ValidateE2EID(id) {
		t.Error("an E2EID with an unregistered ISPB must not validate")
	}
}

func TestParseE2EID_Malformed(t *testing.T) {
	ts := time.Date(2026, 9, 26, 14, 30, 0, 0, time.UTC)
	valid := e2e("60701190", ts, "abc12345678")

	cases := map[string]string{
		"empty":            "",
		"too short":        valid[:31],
		"too long":         valid + "x",
		"wrong prefix":     "X" + valid[1:],
		"letters in ISPB":  "E6070119A" + valid[9:],
		"impossible month": "E60701190" + "202613261430" + "abc12345678",
		"impossible day":   "E60701190" + "202609321430" + "abc12345678",
		"impossible hour":  "E60701190" + "202609262530" + "abc12345678",
		"symbol in seq":    valid[:21] + "abc-2345678",
	}
	for name, id := range cases {
		if _, ok := ParseE2EID(id); ok {
			t.Errorf("%s: malformed E2EID accepted: %q", name, id)
		}
	}
}

func TestParseE2EID_LowercasePrefix(t *testing.T) {
	ts := time.Date(2026, 9, 26, 14, 30, 0, 0, time.UTC)
	id := "e" + e2e("60701190", ts, "abc12345678")[1:]
	if _, ok := ParseE2EID(id); !ok {
		t.Error("a lowercase prefix should still parse")
	}
}

// Every registered ISPB must produce a valid E2EID, so the registry and the
// parser cannot drift apart.
func TestValidateE2EID_AllRegisteredISPBsWork(t *testing.T) {
	ispbOnce.Do(loadISPB)
	ts := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	checked := 0
	for ispb := range ispbIndex {
		if !ValidateE2EID(e2e(ispb, ts, "00000000001")) {
			t.Fatalf("registered ISPB %s produced an invalid E2EID", ispb)
		}
		checked++
	}
	if checked < 400 {
		t.Fatalf("only %d ISPBs checked", checked)
	}
}

func BenchmarkValidateE2EID(b *testing.B) {
	id := fmt.Sprintf("E60701190%s%s", "202609261430", "abc12345678")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ValidateE2EID(id)
	}
}
