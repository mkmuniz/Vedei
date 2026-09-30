// Package engine assembles the detection engines into the sets a caller uses.
package engine

import (
	"github.com/mkmuniz/vedei/detect"
	brengine "github.com/mkmuniz/vedei/engine/br"
	"github.com/mkmuniz/vedei/engine/secrets"
)

// All returns every engine: Brazilian sensitive data and leaked credentials.
//
// The Brazilian engine comes first so that a value both engines can match —
// a CPF used as a Pix key, say — is reported with its specific type rather
// than a generic one.
func All() *detect.Multi {
	return detect.NewMulti(brengine.New(), secrets.New())
}

// Offline returns only the engines that make no network call, for the agent
// hook and for logging middleware, where a request is not acceptable at any
// latency.
func Offline() *detect.Multi {
	return All().OfflineOnly()
}

// BrazilianOnly returns just the Brazilian data engine, for callers that do
// not want the cost of compiling several hundred secret rules.
func BrazilianOnly() *detect.Multi {
	return detect.NewMulti(brengine.New())
}
