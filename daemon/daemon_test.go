package daemon_test

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mkmuniz/nadzor/daemon"
	"github.com/mkmuniz/nadzor/detect"
	"github.com/mkmuniz/nadzor/engine"
	"github.com/mkmuniz/nadzor/stream"
)

// testCPF is a structurally valid CPF used across the suite.
const testCPF = "529.982.247-25"

// socketPath returns a short path for a test socket.
//
// t.TempDir embeds the test name, and a Unix socket path is capped at 104
// bytes on macOS, so the usual temp directory overflows on the longer test
// names here.
func socketPath(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "nz")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, "sock")
}

// start brings up a server on a socket in a temp directory and returns its
// path, so a test never touches the real one.
func start(t *testing.T, opts ...daemon.ServerOption) (string, *daemon.Server) {
	t.Helper()

	p, err := stream.New(engine.BrazilianOnly())
	if err != nil {
		t.Fatalf("stream.New: %v", err)
	}
	path := socketPath(t)
	srv := daemon.NewServer(p, path, opts...)
	if err := srv.Listen(context.Background()); err != nil {
		t.Fatalf("Listen: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx) }()

	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Serve: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("Serve did not return after cancellation")
		}
	})
	return path, srv
}

func dial(t *testing.T, path string) *daemon.Client {
	t.Helper()
	c, err := daemon.Dial(context.Background(), path)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func TestRedact_ReplacesTheValue(t *testing.T) {
	path, _ := start(t)
	c := dial(t, path)

	resp, err := c.Redact(context.Background(), "cpf "+testCPF+" fim", detect.Metadata{Source: "test"})
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}
	if !resp.Redacted {
		t.Fatal("Redacted is false")
	}
	if strings.Contains(resp.Text, testCPF) {
		t.Fatalf("the value survived: %s", resp.Text)
	}
	if len(resp.Findings) != 1 || resp.Findings[0].Type != "cpf" {
		t.Fatalf("findings = %+v", resp.Findings)
	}
}

// The process boundary is where ADR-003 stops being a convention: the raw
// value has to be absent from the wire, not merely unused by the client.
func TestRedact_RawValueNeverCrossesTheSocket(t *testing.T) {
	path, _ := start(t)

	conn, err := new(net.Dialer).DialContext(context.Background(), "unix", path)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	req, err := json.Marshal(daemon.Request{Text: "cpf " + testCPF, Source: "test"})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if _, err := conn.Write(append(req, '\n')); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}

	buf := make([]byte, 64<<10)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if wire := string(buf[:n]); strings.Contains(wire, testCPF) {
		t.Fatalf("the raw value crossed the socket: %s", wire)
	}
}

func TestRedact_CleanTextIsUnchanged(t *testing.T) {
	path, _ := start(t)
	c := dial(t, path)

	const in = "nada de sensivel aqui\ncom duas linhas\n"
	resp, err := c.Redact(context.Background(), in, detect.Metadata{})
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}
	if resp.Text != in {
		t.Fatalf("text changed: %q", resp.Text)
	}
	if resp.Redacted || resp.Degraded {
		t.Fatalf("resp = %+v", resp)
	}
}

// Line framing only works because encoding/json escapes newlines. A value
// sitting next to one is the case that would break a naive framing.
func TestRedact_TextWithNewlinesSurvivesFraming(t *testing.T) {
	path, _ := start(t)
	c := dial(t, path)

	in := "linha 1\ncpf " + testCPF + "\nlinha 3\n"
	resp, err := c.Redact(context.Background(), in, detect.Metadata{})
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}
	if !strings.HasPrefix(resp.Text, "linha 1\n") || !strings.HasSuffix(resp.Text, "\nlinha 3\n") {
		t.Fatalf("framing mangled the text: %q", resp.Text)
	}
	if strings.Contains(resp.Text, testCPF) {
		t.Fatalf("the value survived: %q", resp.Text)
	}
}

func TestRedact_ManyRequestsOnOneConnection(t *testing.T) {
	path, srv := start(t)
	c := dial(t, path)

	for i := range 20 {
		resp, err := c.Redact(context.Background(), "cpf "+testCPF, detect.Metadata{})
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		if !resp.Redacted {
			t.Fatalf("request %d was not redacted", i)
		}
	}
	if got := srv.Served(); got != 20 {
		t.Fatalf("Served() = %d, want 20", got)
	}
}

func TestServer_ConcurrentClients(t *testing.T) {
	path, srv := start(t)

	const clients, each = 8, 10
	var wg sync.WaitGroup
	errs := make(chan error, clients)
	for range clients {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := daemon.Dial(context.Background(), path)
			if err != nil {
				errs <- err
				return
			}
			defer func() { _ = c.Close() }()
			for range each {
				if _, err := c.Redact(context.Background(), "cpf "+testCPF, detect.Metadata{}); err != nil {
					errs <- err
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent client: %v", err)
	}
	if got := srv.Served(); got != clients*each {
		t.Fatalf("Served() = %d, want %d", got, clients*each)
	}
}

// A request the server cannot parse must still get an answer, so a client
// waiting on the socket is never left hanging.
func TestServer_MalformedRequestGetsAnAnswer(t *testing.T) {
	path, _ := start(t)

	conn, err := new(net.Dialer).DialContext(context.Background(), "unix", path)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	if _, err := conn.Write([]byte("nao e json\n")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}

	buf := make([]byte, 4<<10)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	var resp daemon.Response
	if err := json.Unmarshal(buf[:n], &resp); err != nil {
		t.Fatalf("the answer is not a Response: %q", buf[:n])
	}
	if !resp.Degraded {
		t.Fatalf("resp = %+v, want Degraded", resp)
	}
}

func TestClient_RetriesAfterTheDaemonRestarts(t *testing.T) {
	p, err := stream.New(engine.BrazilianOnly())
	if err != nil {
		t.Fatalf("stream.New: %v", err)
	}
	path := socketPath(t)

	serve := func() (*daemon.Server, context.CancelFunc, <-chan error) {
		srv := daemon.NewServer(p, path)
		if err := srv.Listen(context.Background()); err != nil {
			t.Fatalf("Listen: %v", err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- srv.Serve(ctx) }()
		return srv, cancel, done
	}

	_, stop, done := serve()
	c := dial(t, path)
	if _, err := c.Redact(context.Background(), "cpf "+testCPF, detect.Metadata{}); err != nil {
		t.Fatalf("first request: %v", err)
	}

	stop()
	<-done

	_, stop2, done2 := serve()
	defer func() { stop2(); <-done2 }()

	resp, err := c.Redact(context.Background(), "cpf "+testCPF, detect.Metadata{})
	if err != nil {
		t.Fatalf("after restart: %v", err)
	}
	if !resp.Redacted {
		t.Fatal("the retried request was not redacted")
	}
}

func TestListen_RefusesASecondDaemon(t *testing.T) {
	path, _ := start(t)

	p, err := stream.New(engine.BrazilianOnly())
	if err != nil {
		t.Fatalf("stream.New: %v", err)
	}
	second := daemon.NewServer(p, path)
	if err := second.Listen(context.Background()); !errors.Is(err, daemon.ErrAlreadyRunning) {
		t.Fatalf("Listen() error = %v, want ErrAlreadyRunning", err)
	}
}

// A socket file left behind by a killed daemon must not block the next one,
// which is the difference between a crash and a crash plus manual cleanup.
func TestListen_RebindsOverAStaleSocket(t *testing.T) {
	path := socketPath(t)
	if err := os.WriteFile(path, []byte("stale"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	p, err := stream.New(engine.BrazilianOnly())
	if err != nil {
		t.Fatalf("stream.New: %v", err)
	}
	srv := daemon.NewServer(p, path)
	if err := srv.Listen(context.Background()); err != nil {
		t.Fatalf("Listen over a stale socket: %v", err)
	}
	defer func() { _ = srv.Close() }()

	if !daemon.Available(context.Background(), path) {
		t.Fatal("the rebound socket does not answer")
	}
}

// The socket carries text that was just judged sensitive, so its mode is a
// security property, not a detail.
func TestListen_SocketAndDirectoryArePrivate(t *testing.T) {
	path, _ := start(t)

	st, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if perm := st.Mode().Perm(); perm != 0o600 {
		t.Fatalf("socket mode = %o, want 600", perm)
	}

	dir, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatalf("Stat the directory: %v", err)
	}
	if perm := dir.Mode().Perm(); perm != 0o700 {
		t.Fatalf("directory mode = %o, want 700", perm)
	}
}

func TestClose_RemovesTheSocket(t *testing.T) {
	p, err := stream.New(engine.BrazilianOnly())
	if err != nil {
		t.Fatalf("stream.New: %v", err)
	}
	path := socketPath(t)
	srv := daemon.NewServer(p, path)
	if err := srv.Listen(context.Background()); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	if err := srv.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("the socket file survived Close: %v", err)
	}
	// Close is called both by Serve's defer and by a caller, so it has to be
	// safe twice.
	if err := srv.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func TestServe_ExitsAfterTheIdleTimeout(t *testing.T) {
	p, err := stream.New(engine.BrazilianOnly())
	if err != nil {
		t.Fatalf("stream.New: %v", err)
	}
	path := socketPath(t)
	srv := daemon.NewServer(p, path, daemon.WithIdleTimeout(300*time.Millisecond))
	if err := srv.Listen(context.Background()); err != nil {
		t.Fatalf("Listen: %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- srv.Serve(context.Background()) }()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Serve did not exit after the idle timeout")
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("the socket survived the idle exit: %v", err)
	}
}

func TestServe_BeforeListenIsAnError(t *testing.T) {
	p, err := stream.New(engine.BrazilianOnly())
	if err != nil {
		t.Fatalf("stream.New: %v", err)
	}
	srv := daemon.NewServer(p, socketPath(t))
	if err := srv.Serve(context.Background()); err == nil {
		t.Fatal("Serve without Listen returned nil")
	}
}

func TestAvailable(t *testing.T) {
	path, _ := start(t)
	if !daemon.Available(context.Background(), path) {
		t.Fatal("Available said no while the server is up")
	}
	if daemon.Available(context.Background(), socketPath(t)) {
		t.Fatal("Available said yes for a path with no socket")
	}
	if daemon.Available(context.Background(), "") {
		t.Fatal("Available said yes for an empty path")
	}
}

func TestDial_FailsWithoutADaemon(t *testing.T) {
	if _, err := daemon.Dial(context.Background(), socketPath(t)); err == nil {
		t.Fatal("Dial to nothing returned no error")
	}
}

func TestClient_RefusesARequestOverTheLimit(t *testing.T) {
	path, _ := start(t)
	c := dial(t, path)

	if _, err := c.Redact(context.Background(), strings.Repeat("a", daemon.MaxRequest+1), detect.Metadata{}); err == nil {
		t.Fatal("an oversized request was accepted")
	}
}

func TestDefaultSocket_HonoursTheEnvironment(t *testing.T) {
	t.Setenv("NADZOR_SOCKET", "/tmp/explicit.sock")
	if got := daemon.DefaultSocket(); got != "/tmp/explicit.sock" {
		t.Fatalf("DefaultSocket() = %q", got)
	}

	t.Setenv("NADZOR_SOCKET", "")
	t.Setenv("XDG_RUNTIME_DIR", "/run/user/1000")
	if got, want := daemon.DefaultSocket(), "/run/user/1000/nadzor/sock"; got != want {
		t.Fatalf("DefaultSocket() = %q, want %q", got, want)
	}
}
