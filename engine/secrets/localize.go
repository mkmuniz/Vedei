package secrets

import (
	"regexp"
	"strings"
)

// The upstream secret rules key on English names: password, passwd, key,
// secret, token, credential, access, auth. A credential assigned to a variable
// named in Portuguese or Spanish never reaches them. Measured on real-looking
// secrets under equivalent key names, betterleaks finds 100% in English, 57% in
// Spanish and 29% in Portuguese: senha, segredo and senha_banco are never
// recognized at all.
//
// The fix is not a parallel rule set. The upstream rules carry filters with
// English baked into them too — generic-password suppresses an unquoted
// "password = variable" in code by matching the word "password" — so a copied
// regex with translated keywords would recover recall and lose that precision.
// Instead, key names are translated and the text is scanned again by the same
// rules, so every filter applies exactly as it does in English. Parity is the
// target: a Portuguese key name is treated like its English equivalent, no
// better and no worse.
//
// Only key names are rewritten, never values. That is what makes the second pass
// safe to merge: the engine locates each secret in the original text by
// substring search, and a value the translation never touched is found exactly
// where it was.

// keyTranslations maps a Portuguese or Spanish stem to the English word the
// upstream rules recognize. Longest first, so "credenciais" is not consumed as
// "credencial" plus a stray "s".
var keyTranslations = []struct{ from, to string }{
	{"credenciales", "credentials"},
	{"credenciais", "credentials"},
	{"autenticação", "auth"},
	{"autenticacao", "auth"},
	{"autenticación", "auth"},
	{"autenticacion", "auth"},
	{"contraseña", "password"},
	{"contrasena", "password"},
	{"credencial", "credential"},
	{"segredo", "secret"},
	{"secreto", "secret"},
	{"acesso", "access"},
	{"acceso", "access"},
	{"senha", "password"},
	{"chave", "key"},
	{"clave", "key"},
}

// stemRe is the cheap gate: most text holds none of these words, and it should
// cost one regexp scan to find that out, not an identifier walk.
var stemRe = func() *regexp.Regexp {
	parts := make([]string, 0, len(keyTranslations))
	for _, t := range keyTranslations {
		parts = append(parts, regexp.QuoteMeta(t.from))
	}
	return regexp.MustCompile(`(?i)` + strings.Join(parts, "|"))
}()

// identRe matches a key name: letters in any script, digits, and the
// separators key names are written with.
var identRe = regexp.MustCompile(`[\p{L}\p{N}_.\-]+`)

// assignRe matches what follows a key name in an assignment. It mirrors the
// upstream generic rules, which allow up to three quote, space or backslash
// characters between the name and the operator — enough for "senha =",
// `"senha":`, `'senha' =>` and `SENHA=`.
var assignRe = regexp.MustCompile(`^[ \t'"\\]{0,3}(?:=>|:=|=|:)`)

// localizeKeys returns text with Portuguese and Spanish key names translated to
// English, and whether anything changed.
//
// A name is translated only where it is being assigned to. "A senha expirou" is
// prose and stays as it is; the upstream rules would ignore it either way, but
// rewriting prose would also rewrite the value side of a line, and the value is
// the one thing this pass must never touch.
func localizeKeys(text string) (string, bool) {
	if !stemRe.MatchString(text) {
		return text, false
	}

	var b strings.Builder
	last, changed := 0, false

	for _, loc := range identRe.FindAllStringIndex(text, -1) {
		start, end := loc[0], loc[1]
		if !assignRe.MatchString(text[end:]) {
			continue
		}
		ident := text[start:end]
		translated, ok := translateIdent(ident)
		if !ok {
			continue
		}
		if !changed {
			b.Grow(len(text) + 64)
		}
		b.WriteString(text[last:start])
		b.WriteString(translated)
		last, changed = end, true
	}

	if !changed {
		return text, false
	}
	b.WriteString(text[last:])
	return b.String(), true
}

// translateIdent rewrites the stems inside one key name.
//
// The result is lower case unless the name was entirely upper case, which keeps
// environment variables recognizable: SENHA_BANCO becomes PASSWORD_BANCO. Case
// elsewhere does not matter to the rules this feeds, which match key names
// case-insensitively — the one exception, "api", is not a stem translated here.
func translateIdent(ident string) (string, bool) {
	if !stemRe.MatchString(ident) {
		return ident, false
	}
	out := strings.ToLower(ident)
	for _, t := range keyTranslations {
		out = strings.ReplaceAll(out, t.from, t.to)
	}
	out = passwordLast(out)
	if ident == strings.ToUpper(ident) {
		out = strings.ToUpper(out)
	}
	return out, true
}

// passwordLast moves a leading "password" segment to the end of a key name:
// password_banco becomes banco_password.
//
// Word order is the reason. English names are head-final — db_password — and
// the upstream password rule depends on it: it requires a word boundary right
// after "password", so password_db is missed even in English. Portuguese and
// Spanish are head-initial — senha_banco, contraseña_bd — so a straight
// translation lands on exactly the order the rule cannot see. Moving the word
// gives the rule the name an English speaker would have written. The other
// stems need no such step, because the rules they feed allow text after the
// keyword.
func passwordLast(name string) string {
	const word = "password"
	if !strings.HasPrefix(name, word) || len(name) <= len(word)+1 {
		return name
	}
	sep := name[len(word)]
	if sep != '_' && sep != '-' && sep != '.' {
		return name
	}
	return name[len(word)+1:] + string(sep) + word
}
