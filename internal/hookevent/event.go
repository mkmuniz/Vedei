// Package hookevent parses and rewrites a coding agent's hook event.
//
// It is shared by the full nadzor binary and by the thin hook client, which
// exists so the hook does not pay for loading a 26 MB binary; keeping the
// event handling here is what lets the client stay small.
package hookevent

import "encoding/json"

// Fields are the keys a tool result may arrive under, in the order they are
// tried. Agents differ and change; rather than one schema per agent, the event
// is decoded generically and the first matching key wins. An unrecognized
// event passes through untouched.
var Fields = []string{
	"tool_response", // Claude Code
	"tool_result",
	"output", // Codex
	"tool_output",
	"result",
}

// Redactor returns the replacement for text, and false when nothing should
// change. Returning false is not an error: most tool results are clean.
type Redactor func(text string) (string, bool)

// Rewrite returns the event with its tool output replaced by redact's answer.
//
// Every failure returns input unchanged: malformed JSON, no recognized field,
// a structured rather than textual result, a redactor that declines. This is
// the fail-open rule of ADR-005 expressed as a single return value — a hook
// that blocks is worse than a hook that misses something.
func Rewrite(input []byte, redact Redactor) []byte {
	var event map[string]json.RawMessage
	if err := json.Unmarshal(input, &event); err != nil {
		return input
	}

	field, text, ok := Find(event)
	if !ok || text == "" {
		return input
	}

	replacement, changed := redact(text)
	if !changed {
		return input
	}

	encoded, err := json.Marshal(replacement)
	if err != nil {
		return input
	}
	event[field] = encoded

	out, err := json.Marshal(event)
	if err != nil {
		return input
	}
	return out
}

// Find returns the field holding the tool output, if the event has one.
func Find(event map[string]json.RawMessage) (field, text string, ok bool) {
	for _, k := range Fields {
		raw, present := event[k]
		if !present {
			continue
		}
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			// The field exists but is not a string — a structured result.
			// Leave it alone rather than guess at its shape.
			continue
		}
		return k, s, true
	}
	return "", "", false
}
