package redact

import (
	"strings"
	"testing"
)

func TestMask_KeepsShape(t *testing.T) {
	cases := map[string]string{
		"529.982.247-25":     "***.***.***-25",
		"11.222.333/0001-81": "**.***.***/****-81",
		"4539578763621486":   "**************86",
		"joao@exemplo.com":   "****@*******.*om",
	}
	for in, want := range cases {
		if got := Mask(in); got != want {
			t.Errorf("Mask(%q) = %q, want %q", in, got, want)
		}
	}
}

// The point of masking: the value must not be recoverable from the output.
func TestMask_HidesTheInformativeDigits(t *testing.T) {
	const cpf = "529.982.247-25"
	masked := Mask(cpf)
	// The nine digits that carry the identity must all be gone.
	for _, d := range "529982247" {
		if strings.ContainsRune(strings.ReplaceAll(masked, "25", ""), d) {
			t.Errorf("digit %c survived masking: %s", d, masked)
		}
	}
}

func TestMask_Empty(t *testing.T) {
	if Mask("") != "" {
		t.Error("empty input should mask to empty")
	}
}

func TestMask_ShortValue(t *testing.T) {
	// Nothing to hide if the value is shorter than what we keep.
	if got := Mask("ab"); got != "ab" {
		t.Errorf("Mask(ab) = %q", got)
	}
}
