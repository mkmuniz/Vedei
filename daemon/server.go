package daemon

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mkmuniz/vedei/stream"
)

// maxSocketPath is the kernel's limit on a Unix socket path: sun_path is a
// fixed-size array, 104 bytes on the BSDs and macOS, 108 on Linux. Exceeding
// it fails with a bare EINVAL, which says nothing about the cause, so the
// limit is checked here and reported with the fix.
func maxSocketPath() int {
	if runtime.GOOS == "darwin" || runtime.GOOS == "freebsd" || runtime.GOOS == "openbsd" {
		return 104
	}
	return 108
}

// ErrAlreadyRunning means another daemon answers on that socket. It is
// distinguished from a stale socket file, which is removed and rebound,
// because removing a live daemon's socket would silently orphan it.
var ErrAlreadyRunning = errors.New("daemon: another vedei daemon is listening on this socket")

// Server answers redaction requests over a Unix socket.
//
// It exists for one reason: a process that starts per tool call spends ~12 ms
// on spawn and ~14 ms compiling the secret rules to do ~0.3 ms of work. The
// rules are compiled once here and the per-call cost becomes a round trip.
//
// The socket is Unix-domain only. There is no TCP mode and there should never
// be one: everything that crosses it is text that was just judged sensitive.
type Server struct {
	proc *stream.Processor
	path string

	idle     time.Duration
	logw     io.Writer
	maxConns int

	ln       net.Listener
	lastUsed atomic.Int64 // UnixNano
	inFlight atomic.Int64
	served   atomic.Int64

	closeOnce sync.Once
}

// ServerOption configures a Server.
type ServerOption func(*Server)

// WithIdleTimeout makes the server exit after d without a request. Zero, the
// default, means it runs until stopped.
func WithIdleTimeout(d time.Duration) ServerOption {
	return func(s *Server) { s.idle = d }
}

// WithLog sets where the server reports accept and handler failures. Requests
// themselves are never logged: the text carries the values being redacted.
func WithLog(w io.Writer) ServerOption {
	return func(s *Server) { s.logw = w }
}

// WithMaxConns caps concurrent connections. Beyond the cap a connection is
// accepted and closed at once, so a client sees a failure quickly and falls
// back in-process rather than waiting on a queue.
func WithMaxConns(n int) ServerOption {
	return func(s *Server) { s.maxConns = n }
}

// NewServer returns a server that answers with proc, listening on path.
func NewServer(proc *stream.Processor, path string, opts ...ServerOption) *Server {
	s := &Server{proc: proc, path: path, logw: io.Discard, maxConns: 64}
	for _, o := range opts {
		o(s)
	}
	s.lastUsed.Store(time.Now().UnixNano())
	return s
}

// Listen binds the socket. It is separate from Serve so a caller — or a test
// — knows the socket exists before anything is expected to connect to it.
func (s *Server) Listen(ctx context.Context) error {
	if n := len(s.path); n >= maxSocketPath() {
		return fmt.Errorf("daemon: socket path is %d bytes and the kernel allows %d; "+
			"set VEDEI_SOCKET or --socket to something shorter", n, maxSocketPath()-1)
	}

	if err := prepareDir(filepath.Dir(s.path)); err != nil {
		return err
	}

	if err := s.clearStaleSocket(ctx); err != nil {
		return err
	}

	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "unix", s.path)
	if err != nil {
		return fmt.Errorf("daemon: listening on %s: %w", s.path, err)
	}
	if err := os.Chmod(s.path, 0o600); err != nil {
		_ = ln.Close()
		return fmt.Errorf("daemon: restricting %s: %w", s.path, err)
	}
	s.ln = ln
	return nil
}

// prepareDir makes sure the socket's directory exists and cannot be used to
// substitute the socket.
//
// A directory we create is ours to restrict to 0700. One that already exists
// is not: the socket may legitimately sit in a shared directory, and chmod on
// /tmp either fails or breaks the system. What matters there is that nobody
// else can unlink the socket and bind their own in its place, which the sticky
// bit is exactly what prevents.
func prepareDir(dir string) error {
	st, err := os.Stat(dir)
	switch {
	case os.IsNotExist(err):
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("daemon: creating %s: %w", dir, err)
		}
		// MkdirAll's mode is masked by umask, so it is set again explicitly.
		if err := os.Chmod(dir, 0o700); err != nil { //#nosec G302 -- this is a directory, not a file: 0700 is the restriction, and it is asserted by TestListen_SocketAndDirectoryArePrivate
			return fmt.Errorf("daemon: restricting %s: %w", dir, err)
		}
		return nil
	case err != nil:
		return fmt.Errorf("daemon: checking %s: %w", dir, err)
	case !st.IsDir():
		return fmt.Errorf("daemon: %s is not a directory", dir)
	}

	mode := st.Mode()
	if mode.Perm()&0o002 != 0 && mode&os.ModeSticky == 0 {
		return fmt.Errorf("daemon: %s is world-writable and not sticky, so another user "+
			"could replace the socket; pick a private directory with --socket", dir)
	}
	return nil
}

// clearStaleSocket removes a socket file left behind by a dead daemon, and
// refuses when a live one answers.
func (s *Server) clearStaleSocket(ctx context.Context) error {
	if _, err := os.Lstat(s.path); err != nil {
		return nil // nothing there, or not ours to judge
	}
	conn, err := dialSocket(ctx, s.path, 200*time.Millisecond)
	if err == nil {
		_ = conn.Close()
		return ErrAlreadyRunning
	}
	if err := os.Remove(s.path); err != nil {
		return fmt.Errorf("daemon: removing stale socket %s: %w", s.path, err)
	}
	return nil
}

// Addr returns the socket path the server is bound to.
func (s *Server) Addr() string { return s.path }

// Served returns how many requests have been answered. It is here for the
// idle test and for a status line, not for metrics.
func (s *Server) Served() int64 { return s.served.Load() }

// Serve answers requests until ctx is cancelled, the idle timeout elapses, or
// Close is called. Listen must have run first.
func (s *Server) Serve(ctx context.Context) error {
	if s.ln == nil {
		return errors.New("daemon: Serve called before Listen")
	}
	defer func() { _ = s.Close() }()

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Accept blocks, so cancellation has to arrive by closing the listener
	// rather than by checking ctx at the top of the loop.
	closed := make(chan struct{})
	go func() {
		defer close(closed)
		<-ctx.Done()
		_ = s.ln.Close()
	}()

	idleDone := s.watchIdle(ctx, cancel)

	var wg sync.WaitGroup
	var acceptErr error
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			if ctx.Err() == nil && !errors.Is(err, net.ErrClosed) {
				acceptErr = fmt.Errorf("daemon: accept: %w", err)
			}
			break
		}
		if s.inFlight.Load() >= int64(s.maxConns) {
			s.logf("refused a connection: %d already in flight", s.maxConns)
			_ = conn.Close()
			continue
		}
		s.inFlight.Add(1)
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer s.inFlight.Add(-1)
			defer func() {
				if r := recover(); r != nil {
					// The redaction path is fail-open, so a panic here must
					// not take down a daemon other sessions depend on.
					s.logf("handler panicked: %v", r)
				}
			}()
			s.handle(ctx, conn)
		}()
	}

	cancel()
	wg.Wait()
	<-idleDone
	<-closed
	return acceptErr
}

// watchIdle cancels the server once it has been unused for the idle window.
func (s *Server) watchIdle(ctx context.Context, cancel context.CancelFunc) <-chan struct{} {
	done := make(chan struct{})
	if s.idle <= 0 {
		close(done)
		return done
	}
	go func() {
		defer close(done)
		tick := time.NewTicker(s.idle / 4)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				if s.inFlight.Load() > 0 {
					continue
				}
				since := time.Since(time.Unix(0, s.lastUsed.Load()))
				if since >= s.idle {
					s.logf("exiting after %s idle", since.Truncate(time.Second))
					_ = s.ln.Close()
					cancel()
					return
				}
			}
		}
	}()
	return done
}

// Close stops the listener and removes the socket file.
func (s *Server) Close() error {
	var err error
	s.closeOnce.Do(func() {
		if s.ln != nil {
			err = s.ln.Close()
		}
		// net closes and unlinks its own socket; removing again is harmless
		// and covers the case where Listen bound it and Serve never ran.
		_ = os.Remove(s.path)
	})
	return err
}

// handle answers every request on one connection. Connections are kept open
// so a hook that fires repeatedly pays the connect cost once.
func (s *Server) handle(ctx context.Context, conn net.Conn) {
	defer func() { _ = conn.Close() }()

	// Closing the listener does not close accepted connections, and a client
	// that holds one idle leaves this handler blocked in Scan. Without this,
	// shutdown waits on a reader that has nothing to read, and SIGTERM does
	// not stop the daemon while any agent is still connected.
	gone := make(chan struct{})
	defer close(gone)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-gone:
		}
	}()

	lines := bufio.NewScanner(conn)
	lines.Buffer(make([]byte, 0, 64<<10), MaxRequest)
	enc := json.NewEncoder(conn)

	for lines.Scan() {
		if ctx.Err() != nil {
			return
		}
		s.lastUsed.Store(time.Now().UnixNano())

		var req Request
		if err := json.Unmarshal(lines.Bytes(), &req); err != nil {
			// The request is unreadable, so its text cannot be echoed back.
			// The client's own fallback is what keeps the caller working.
			s.reply(enc, Response{Degraded: true, Error: "malformed request"})
			continue
		}

		out, res := s.proc.Process(ctx, req.Text, req.Metadata())
		resp := Response{
			Text:     out,
			Findings: res.Findings,
			Redacted: res.Redacted,
			Degraded: res.Degraded,
		}
		if res.Err != nil {
			resp.Error = res.Err.Error()
		}
		s.served.Add(1)
		s.reply(enc, resp)
		s.lastUsed.Store(time.Now().UnixNano())
	}

	if err := lines.Err(); err != nil && !errors.Is(err, net.ErrClosed) {
		s.logf("reading a request: %v", err)
	}
}

func (s *Server) reply(enc *json.Encoder, resp Response) {
	if err := enc.Encode(resp); err != nil {
		s.logf("writing a response: %v", err)
	}
}

func (s *Server) logf(format string, args ...any) {
	_, _ = fmt.Fprintf(s.logw, "vedei daemon: "+format+"\n", args...)
}
