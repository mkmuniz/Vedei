package daemon

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/mkmuniz/vedei/detect"
)

// DefaultTimeout bounds one request. It is short on purpose: past this point
// the caller is better off scanning in-process than waiting, because the
// daemon exists to save time, not to become a new place to block.
const DefaultTimeout = 2 * time.Second

// Client talks to a daemon over its Unix socket.
//
// Every method returns an error rather than degrading quietly, so the caller
// owns the fallback. That is deliberate: the fallback is to scan in-process,
// which only the caller can do.
type Client struct {
	path    string
	timeout time.Duration

	mu   sync.Mutex
	conn net.Conn
	br   *bufio.Reader
}

// ClientOption configures a Client.
type ClientOption func(*Client)

// WithTimeout bounds dialing and each request.
func WithTimeout(d time.Duration) ClientOption {
	return func(c *Client) { c.timeout = d }
}

// Dial connects to the daemon listening on path.
func Dial(ctx context.Context, path string, opts ...ClientOption) (*Client, error) {
	c := &Client{path: path, timeout: DefaultTimeout}
	for _, o := range opts {
		o(c)
	}
	if err := c.connect(ctx); err != nil {
		return nil, err
	}
	return c, nil
}

// Available reports whether a daemon answers on path. It connects and hangs
// up, so it costs a round trip and nothing else; it is for a status command,
// not for a check before every request — Dial already tells you.
func Available(ctx context.Context, path string) bool {
	if path == "" {
		return false
	}
	if _, err := os.Lstat(path); err != nil {
		return false
	}
	conn, err := dialSocket(ctx, path, 200*time.Millisecond)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// dialSocket is the one place the socket is dialed, so the timeout and the
// context apply the same way everywhere.
func dialSocket(ctx context.Context, path string, timeout time.Duration) (net.Conn, error) {
	d := net.Dialer{Timeout: timeout}
	return d.DialContext(ctx, "unix", path)
}

func (c *Client) connect(ctx context.Context) error {
	conn, err := dialSocket(ctx, c.path, c.timeout)
	if err != nil {
		return fmt.Errorf("daemon: dialing %s: %w", c.path, err)
	}
	c.conn, c.br = conn, bufio.NewReaderSize(conn, 64<<10)
	return nil
}

// Redact sends text to the daemon and returns what came back.
//
// A request is a pure function of its input, so a connection that died
// between calls — the daemon restarted, the idle timeout fired — is redialed
// and the request is retried exactly once.
func (c *Client) Redact(ctx context.Context, text string, meta detect.Metadata) (Response, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	req := Request{Text: text, Source: meta.Source, Path: meta.Path}
	resp, err := c.roundTrip(req)
	if err == nil {
		return resp, nil
	}

	c.dropConn()
	if err := c.connect(ctx); err != nil {
		return Response{}, err
	}
	return c.roundTrip(req)
}

func (c *Client) roundTrip(req Request) (Response, error) {
	if c.conn == nil {
		return Response{}, errors.New("daemon: client is closed")
	}
	if err := c.conn.SetDeadline(time.Now().Add(c.timeout)); err != nil {
		return Response{}, fmt.Errorf("daemon: setting a deadline: %w", err)
	}

	line, err := json.Marshal(req)
	if err != nil {
		return Response{}, fmt.Errorf("daemon: encoding the request: %w", err)
	}
	if len(line)+1 > MaxRequest {
		return Response{}, fmt.Errorf("daemon: request of %d bytes exceeds the %d byte limit",
			len(line), MaxRequest)
	}
	if _, err := c.conn.Write(append(line, '\n')); err != nil {
		return Response{}, fmt.Errorf("daemon: sending the request: %w", err)
	}

	raw, err := c.br.ReadBytes('\n')
	if err != nil {
		return Response{}, fmt.Errorf("daemon: reading the response: %w", err)
	}
	var resp Response
	if err := json.Unmarshal(raw, &resp); err != nil {
		return Response{}, fmt.Errorf("daemon: decoding the response: %w", err)
	}
	return resp, nil
}

func (c *Client) dropConn() {
	if c.conn != nil {
		_ = c.conn.Close()
	}
	c.conn, c.br = nil, nil
}

// Close hangs up.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn == nil {
		return nil
	}
	err := c.conn.Close()
	c.conn, c.br = nil, nil
	return err
}
