// Package fingerprint computes a stable identifier for a finding, derived
// from its type and normalized value rather than its location, so moving a
// file or adding a line does not invalidate an entry in .nadzorignore.
package fingerprint
