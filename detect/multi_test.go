package detect

import (
	"context"
	"errors"
	"testing"
	"time"
)

type fakeEngine struct {
	name    string
	net     bool
	latency time.Duration
	out     []Finding
	err     error
}

func (f fakeEngine) Name() string { return f.name }
func (f fakeEngine) Capabilities() Capabilities {
	return Capabilities{RequiresNetwork: f.net, TypicalLatency: f.latency, Deterministic: !f.net}
}
func (f fakeEngine) Scan(context.Context, []byte, Metadata) ([]Finding, error) {
	return f.out, f.err
}

func finding(fp string, line int) Finding {
	return Finding{Fingerprint: fp, Locations: []Location{{Line: line}}}
}

func TestMulti_MergesFindings(t *testing.T) {
	m := NewMulti(
		fakeEngine{name: "a", out: []Finding{finding("f1", 3)}},
		fakeEngine{name: "b", out: []Finding{finding("f2", 1)}},
	)
	got, err := m.Scan(context.Background(), []byte("x"), Metadata{})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 findings, got %d", len(got))
	}
	// Ordered by location, not by engine.
	if got[0].Fingerprint != "f2" {
		t.Errorf("findings are not ordered by location: %+v", got)
	}
}

func TestMulti_DeduplicatesAcrossEngines(t *testing.T) {
	m := NewMulti(
		fakeEngine{name: "a", out: []Finding{finding("same", 1)}},
		fakeEngine{name: "b", out: []Finding{finding("same", 5)}},
	)
	got, _ := m.Scan(context.Background(), []byte("x"), Metadata{})
	if len(got) != 1 {
		t.Fatalf("want 1 merged finding, got %d", len(got))
	}
	if len(got[0].Locations) != 2 {
		t.Errorf("locations should merge, got %d", len(got[0].Locations))
	}
}

// ADR-005: a partial failure must not look like a clean scan.
func TestMulti_FailingEngineReturnsErrorAndKeepsOtherFindings(t *testing.T) {
	boom := errors.New("engine exploded")
	m := NewMulti(
		fakeEngine{name: "ok", out: []Finding{finding("f1", 1)}},
		fakeEngine{name: "bad", err: boom},
	)
	got, err := m.Scan(context.Background(), []byte("x"), Metadata{})
	if err == nil {
		t.Fatal("a failing engine must surface an error")
	}
	if !errors.Is(err, boom) {
		t.Errorf("error does not wrap the cause: %v", err)
	}
	if len(got) != 1 {
		t.Errorf("findings from the healthy engine were lost: %+v", got)
	}
}

func TestMulti_CapabilitiesTakeTheMostDemanding(t *testing.T) {
	m := NewMulti(
		fakeEngine{name: "offline", latency: time.Microsecond},
		fakeEngine{name: "online", net: true, latency: 500 * time.Millisecond},
	)
	c := m.Capabilities()
	if !c.RequiresNetwork {
		t.Error("one networked engine makes the set networked")
	}
	if c.Deterministic {
		t.Error("one nondeterministic engine makes the set nondeterministic")
	}
	if c.TypicalLatency < 500*time.Millisecond {
		t.Errorf("latency should be the sum, got %v", c.TypicalLatency)
	}
}

// The hot path needs a way to refuse an engine that would make a request.
func TestMulti_OfflineOnlyDropsNetworkedEngines(t *testing.T) {
	m := NewMulti(
		fakeEngine{name: "offline", out: []Finding{finding("f1", 1)}},
		fakeEngine{name: "online", net: true, out: []Finding{finding("f2", 2)}},
	)
	off := m.OfflineOnly()
	if off.Capabilities().RequiresNetwork {
		t.Fatal("OfflineOnly still requires the network")
	}
	got, _ := off.Scan(context.Background(), []byte("x"), Metadata{})
	if len(got) != 1 || got[0].Fingerprint != "f1" {
		t.Errorf("the networked engine still ran: %+v", got)
	}
}

func TestMulti_CancelledContextStops(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	m := NewMulti(fakeEngine{name: "a", out: []Finding{finding("f1", 1)}})
	if _, err := m.Scan(ctx, []byte("x"), Metadata{}); err == nil {
		t.Error("a cancelled context should stop the scan")
	}
}

func TestMulti_Empty(t *testing.T) {
	got, err := NewMulti().Scan(context.Background(), []byte("x"), Metadata{})
	if err != nil || len(got) != 0 {
		t.Errorf("empty Multi: got %v, %v", got, err)
	}
}
