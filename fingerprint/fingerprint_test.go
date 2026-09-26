package fingerprint

import "testing"

// The point of the package: the same number written differently is the same
// finding, so one ignore entry covers every mask.
func TestOf_MasksCollapse(t *testing.T) {
	want := Of("cpf", "12345678909")
	for _, s := range []string{
		"123.456.789-09",
		"123 456 789 09",
		"123456789-09",
	} {
		if got := Of("cpf", s); got != want {
			t.Errorf("Of(cpf, %q) = %s, want %s", s, got, want)
		}
	}
}

func TestOf_CaseInsensitiveForAlphanumeric(t *testing.T) {
	if Of("cnpj", "12.ABC.345/01DE-35") != Of("cnpj", "12abc34501de35") {
		t.Error("alphanumeric CNPJ should fingerprint the same in any case")
	}
}

// Type is part of the input, so the same digits under two document types are
// two different findings.
func TestOf_TypeDiscriminates(t *testing.T) {
	if Of("cpf", "12345678909") == Of("pis", "12345678909") {
		t.Error("different types must not share a fingerprint")
	}
}

func TestOf_DifferentValuesDiffer(t *testing.T) {
	if Of("cpf", "12345678909") == Of("cpf", "12345678900") {
		t.Error("different values must not share a fingerprint")
	}
}

// Location is deliberately absent from the input; this documents that the
// fingerprint survives a file move.
func TestOf_IsStableAcrossRuns(t *testing.T) {
	a := Of("cpf", "123.456.789-09")
	b := Of("cpf", "123.456.789-09")
	if a != b {
		t.Fatalf("fingerprint is not deterministic: %s != %s", a, b)
	}
	if len(a) != Length {
		t.Errorf("length = %d, want %d", len(a), Length)
	}
}

func BenchmarkOf(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Of("cpf", "123.456.789-09")
	}
}
