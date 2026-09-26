package br

import (
	"regexp"
	"strings"
)

// PixKeyType is the kind of key a Pix address holds.
type PixKeyType string

// The five key types the Pix specification allows.
const (
	PixKeyUnknown PixKeyType = "unknown"
	PixKeyCPF     PixKeyType = "cpf"
	PixKeyCNPJ    PixKeyType = "cnpj"
	PixKeyEmail   PixKeyType = "email"
	PixKeyPhone   PixKeyType = "phone"
	PixKeyEVP     PixKeyType = "evp"
)

var (
	// A random key is a UUID v4, which the spec calls EVP.
	evpRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	// A phone key carries the country code and a valid Brazilian area code.
	phoneRe = regexp.MustCompile(`^\+55([1-9][1-9])(9?\d{8})$`)
	emailRe = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[a-zA-Z]{2,}$`)
)

// ClassifyPixKey returns the type of a Pix key and whether it is structurally
// valid for that type. An unrecognized shape yields PixKeyUnknown, false.
func ClassifyPixKey(s string) (PixKeyType, bool) {
	t := strings.TrimSpace(s)

	switch {
	case strings.HasPrefix(t, "+"):
		return PixKeyPhone, phoneRe.MatchString(t)
	case strings.Contains(t, "@"):
		return PixKeyEmail, emailRe.MatchString(t) && len(t) <= 77
	case evpRe.MatchString(strings.ToLower(t)):
		return PixKeyEVP, true
	}

	switch len(onlyDigits(t)) {
	case CPFLength:
		return PixKeyCPF, ValidateCPF(t)
	case CNPJLength:
		return PixKeyCNPJ, ValidateCNPJ(t)
	}
	if len(normalizeCNPJ(t)) == CNPJLength {
		return PixKeyCNPJ, ValidateCNPJ(t)
	}
	return PixKeyUnknown, false
}

// ValidateChavePix reports whether s is a structurally valid Pix key of any type.
func ValidateChavePix(s string) bool {
	_, ok := ClassifyPixKey(s)
	return ok
}
