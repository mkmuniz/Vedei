package br

// ValidateCIN reports whether s is a structurally valid CIN (Carteira de
// Identidade Nacional).
//
// The CIN uses the CPF as the single national identification number,
// replacing the state-issued RG number, so this is ValidateCPF under the name
// callers will look for.
func ValidateCIN(s string) bool { return ValidateCPF(s) }
