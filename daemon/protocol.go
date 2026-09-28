package daemon

import (
	"os"
	"path/filepath"

	"github.com/mkmuniz/nadzor/detect"
)

// MaxRequest caps one request. A hook result that exceeds it is the caller's
// problem to split; the daemon refuses rather than letting a single client
// decide how much memory this process holds.
const MaxRequest = 16 << 20

// Request is one redaction request: a single JSON object on one line.
//
// Line framing works because encoding/json escapes newlines inside strings,
// so a request can carry arbitrary text without an escape layer of its own.
type Request struct {
	Text   string `json:"text"`
	Source string `json:"source,omitempty"`
	Path   string `json:"path,omitempty"`
}

// Response is the answer to a Request.
//
// Findings serialize through detect.Finding, whose Raw field is json:"-", so
// the process boundary is where ADR-003 is enforced rather than trusted: the
// original value cannot cross this socket even if a caller asks for it.
type Response struct {
	Text     string           `json:"text"`
	Findings []detect.Finding `json:"findings,omitempty"`
	Redacted bool             `json:"redacted"`
	Degraded bool             `json:"degraded,omitempty"`
	Error    string           `json:"error,omitempty"`
}

// Metadata rebuilds the scan metadata a Request describes.
func (r Request) Metadata() detect.Metadata {
	return detect.Metadata{Source: r.Source, Path: r.Path}
}

// DefaultSocket returns the socket path, in order of precedence:
// NADZOR_SOCKET, then $XDG_RUNTIME_DIR/nadzor/sock, then ~/.nadzor/sock.
//
// The runtime directory is preferred where it exists because it is already
// user-private and cleared on logout. macOS has none, so the home directory
// is the portable fallback.
func DefaultSocket() string {
	if p := os.Getenv("NADZOR_SOCKET"); p != "" {
		return p
	}
	if dir := os.Getenv("XDG_RUNTIME_DIR"); dir != "" {
		return filepath.Join(dir, "nadzor", "sock")
	}
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".nadzor", "sock")
	}
	return filepath.Join(os.TempDir(), "nadzor.sock")
}
