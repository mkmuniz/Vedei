// Package secrets adapts betterleaks to the detect.Engine interface, giving
// nadzor its secret-detection rule set without reimplementing it.
//
// The wrapper exists so the rest of the codebase never imports betterleaks
// directly: when its v2 API lands, only this package changes.
package secrets
