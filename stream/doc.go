// Package stream implements the hot path: read text, redact, write it back.
// It is fail-open by design — an internal error lets the text through
// unmodified, because breaking the caller is worse than not redacting.
package stream
