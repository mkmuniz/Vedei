// Package br adapts detect/br to the detect.Engine interface. It declares
// RequiresNetwork=false, which is what allows it to run on the hot path:
// the agent hook and the logging middleware.
package br
