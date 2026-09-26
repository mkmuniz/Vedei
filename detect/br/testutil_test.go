package br

import (
	"fmt"
	"math/rand"
	"strconv"
)

// genCPF builds a CPF whose check digits are correct by construction, so the
// property tests can assert on many cases instead of a handful of examples.
func genCPF(r *rand.Rand) string {
	var d [11]int
	for {
		for i := 0; i < 9; i++ {
			d[i] = r.Intn(10)
		}
		// Reject a base that would produce a repeated sequence; those are
		// invalid by rule and would make the generator contradict the validator.
		same := true
		for i := 1; i < 9; i++ {
			if d[i] != d[0] {
				same = false
				break
			}
		}
		if !same {
			break
		}
	}

	sum := 0
	for i := 0; i < 9; i++ {
		sum += d[i] * (10 - i)
	}
	d[9] = mod11(sum)

	sum = 0
	for i := 0; i < 10; i++ {
		sum += d[i] * (11 - i)
	}
	d[10] = mod11(sum)

	s := ""
	for _, n := range d {
		s += strconv.Itoa(n)
	}
	return s
}

// corrupt returns s with exactly one digit changed, so it must fail any
// check-digit validator.
func corrupt(r *rand.Rand, s string) string {
	b := []byte(s)
	i := r.Intn(len(b))
	orig := b[i]
	for b[i] == orig {
		b[i] = byte('0' + r.Intn(10))
	}
	return string(b)
}

// masks returns the same number written the ways it circulates in the wild.
func masks(cpf string) []string {
	return []string{
		cpf,
		fmt.Sprintf("%s.%s.%s-%s", cpf[0:3], cpf[3:6], cpf[6:9], cpf[9:11]),
		fmt.Sprintf("%s %s %s %s", cpf[0:3], cpf[3:6], cpf[6:9], cpf[9:11]),
		fmt.Sprintf("%s%s%s-%s", cpf[0:3], cpf[3:6], cpf[6:9], cpf[9:11]),
	}
}

// expectedCPFCheckDigits recomputes both check digits from the first nine
// digits, independently of ValidateCPF, so tests can tell a real collision
// from a validator bug.
func expectedCPFCheckDigits(s string) (int, int) {
	d := onlyDigits(s)
	sum := 0
	for i := 0; i < 9; i++ {
		sum += int(d[i]-'0') * (10 - i)
	}
	d1 := mod11(sum)

	sum = 0
	for i := 0; i < 9; i++ {
		sum += int(d[i]-'0') * (11 - i)
	}
	sum += d1 * 2
	return d1, mod11(sum)
}

const cnpjAlphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"

// genCNPJ builds a CNPJ with correct check digits. alpha selects the
// alphanumeric format introduced in July 2026.
func genCNPJ(r *rand.Rand, alpha bool) string {
	body := make([]byte, 12)
	for {
		for i := range body {
			if alpha {
				body[i] = cnpjAlphabet[r.Intn(len(cnpjAlphabet))]
			} else {
				body[i] = byte('0' + r.Intn(10))
			}
		}
		same := true
		for i := 1; i < 12; i++ {
			if body[i] != body[0] {
				same = false
				break
			}
		}
		if !same {
			break
		}
	}

	w := [12]int{5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2}
	sum := 0
	for i := 0; i < 12; i++ {
		sum += (int(body[i]) - 48) * w[i]
	}
	d1 := mod11(sum)

	sum = (int(body[0]) - 48) * 6
	for i := 0; i < 11; i++ {
		sum += (int(body[i+1]) - 48) * w[i]
	}
	sum += d1 * 2
	d2 := mod11(sum)

	return string(body) + strconv.Itoa(d1) + strconv.Itoa(d2)
}
