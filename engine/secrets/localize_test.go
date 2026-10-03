package secrets

import (
	"context"
	"strings"
	"testing"

	"github.com/mkmuniz/vedei/detect"
)

// realSecret is shaped like a credential: mixed case and digits, no words. It
// is assembled so this file carries no single literal another scanner flags.
var realSecret = "8f3kq9zLw2" + "Xc7vB1nM4p"

func TestLocalizeKeys(t *testing.T) {
	tests := []struct {
		name        string
		in          string
		want        string
		wantChanged bool
	}{
		{"quoted assignment", `senha = "v"`, `password = "v"`, true},
		{"env var keeps upper case and reorders", `SENHA_BANCO=v`, `BANCO_PASSWORD=v`, true},
		{"json key", `"segredo": "v"`, `"secret": "v"`, true},
		{"php array key", `'contraseña' => 'v'`, `'password' => 'v'`, true},
		{"go short assignment", `senha := valor`, `password := valor`, true},
		{"yaml", `chave_api: v`, `key_api: v`, true},
		{"longest stem wins", `credenciais: v`, `credentials: v`, true},
		{"accented upper case", `AUTENTICAÇÃO=v`, `AUTH=v`, true},
		{"spanish reorders too", `contrasena_bd = "v"`, `bd_password = "v"`, true},

		// Prose is not an assignment, so it is left alone.
		{"prose", `a senha expirou ontem`, `a senha expirou ontem`, false},
		// The value side is never rewritten, even when it holds a stem: the engine
		// finds secrets from this pass by searching the original text for them.
		{"value holding a stem is untouched", `token = "minhasenha123"`, `token = "minhasenha123"`, false},
		{"nothing to translate", `password = "v"`, `password = "v"`, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, changed := localizeKeys(tt.in)
			if got != tt.want || changed != tt.wantChanged {
				t.Errorf("localizeKeys(%q) = (%q, %v), want (%q, %v)",
					tt.in, got, changed, tt.want, tt.wantChanged)
			}
		})
	}
}

// The measurement behind the localization pass, pinned. Before it, a real
// credential under a Portuguese name was found 29% of the time and under a
// Spanish one 57%, against 100% in English; senha and segredo were never
// recognized at all.
func TestScan_FindsSecretsUnderPortugueseAndSpanishKeys(t *testing.T) {
	tests := []struct {
		name     string
		text     string
		wantType string
	}{
		{"senha", `senha = "` + realSecret + `"`, "generic-password"},
		{"senha, head-initial", `senha_banco = "` + realSecret + `"`, "generic-password"},
		{"senha, env var", `SENHA_BANCO=` + realSecret, "generic-password"},
		{"segredo", `segredo: ` + realSecret, "generic-api-key"},
		{"chave", `chave_autenticacao = "` + realSecret + `"`, "generic-api-key"},
		{"contrasena, head-initial", `contrasena_bd = "` + realSecret + `"`, "generic-password"},
		{"secreto", `secreto_cliente: ` + realSecret, "generic-api-key"},
	}

	e := New()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs, err := e.Scan(context.Background(), []byte(tt.text), detect.Metadata{Path: "config.yaml"})
			if err != nil {
				t.Fatalf("Scan: %v", err)
			}
			var got *detect.Finding
			for i := range fs {
				if fs[i].Type == tt.wantType {
					got = &fs[i]
				}
			}
			if got == nil {
				t.Fatalf("no %s finding in %q; got %d findings", tt.wantType, tt.text, len(fs))
			}

			// The offsets must point at the value in the original text, which is
			// what lets the redaction path mask it even though it was found in a
			// translated copy.
			loc := got.Locations[0]
			if span := tt.text[loc.ByteStart:loc.ByteEnd]; span != realSecret {
				t.Errorf("location selects %q, want the secret", span)
			}
		})
	}
}

// A value both passes report is one finding, not two: same rule, same value,
// same fingerprint.
func TestScan_LocalizedPassDoesNotDuplicate(t *testing.T) {
	text := "password = \"" + realSecret + "\"\nsenha = \"" + realSecret + "\"\n"
	fs, err := New().Scan(context.Background(), []byte(text), detect.Metadata{Path: "config.yaml"})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	n := 0
	for _, f := range fs {
		if strings.Contains(f.Type, "password") {
			n++
		}
	}
	if n != 1 {
		t.Errorf("got %d generic-password findings, want 1 deduplicated", n)
	}
}
