// Package br implements detection and structural validation of Brazilian
// sensitive data: CPF, CNPJ, CIN, CNH, PIS, título de eleitor, CNS, card PAN,
// Pix keys and Pix end-to-end IDs.
//
// Everything here is pure: no IO, no network, no dependencies outside the
// standard library. Validation answers whether a value is structurally real
// (its check digit closes), never whether it belongs to a real person. This
// package must never query an official registry.
package br
