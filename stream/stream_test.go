package stream

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/mkmuniz/nadzor/detect"
	"github.com/mkmuniz/nadzor/engine"
)

const cpf = "529.982.247-25"

func proc(t *testing.T, opts ...Option) *Processor {
	t.Helper()
	p, err := New(engine.Offline(), opts...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return p
}

func TestProcess_RedactsTheValue(t *testing.T) {
	out, res := proc(t).Process(context.Background(), "meu cpf e "+cpf+" ok", detect.Metadata{})

	if strings.Contains(out, cpf) {
		t.Fatalf("the value survived: %s", out)
	}
	if !res.Redacted {
		t.Error("Redacted should be true")
	}
	if !strings.Contains(out, "nadzor") {
		t.Errorf("the reader is not told something was removed: %s", out)
	}
	// The surrounding text must be intact.
	if !strings.HasPrefix(out, "meu cpf e ") || !strings.HasSuffix(out, " ok") {
		t.Errorf("surrounding text was damaged: %s", out)
	}
}

func TestProcess_LeavesCleanTextUntouched(t *testing.T) {
	const in = "nao ha nada de sensivel nesta linha"
	out, res := proc(t).Process(context.Background(), in, detect.Metadata{})
	if out != in {
		t.Errorf("clean text was modified: %q", out)
	}
	if res.Redacted {
		t.Error("Redacted should be false")
	}
}

func TestProcess_MultipleValuesAllReplaced(t *testing.T) {
	in := "cpf " + cpf + " e cnpj 11.222.333/0001-81 fim"
	out, res := proc(t).Process(context.Background(), in, detect.Metadata{})

	if strings.Contains(out, cpf) || strings.Contains(out, "11.222.333/0001-81") {
		t.Fatalf("a value survived: %s", out)
	}
	if len(res.Findings) != 2 {
		t.Errorf("want 2 findings, got %d", len(res.Findings))
	}
	if !strings.HasSuffix(out, " fim") {
		t.Errorf("replacement shifted the tail: %s", out)
	}
}

// ADR-005 on this path: an engine failure must not break the caller.
type panickingEngine struct{}

func (panickingEngine) Name() string                      { return "panics" }
func (panickingEngine) Capabilities() detect.Capabilities { return detect.Capabilities{} }
func (panickingEngine) Scan(context.Context, []byte, detect.Metadata) ([]detect.Finding, error) {
	panic("boom")
}

func TestProcess_FailsOpenOnPanic(t *testing.T) {
	p, err := New(panickingEngine{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	const in = "texto com cpf " + cpf

	out, res := p.Process(context.Background(), in, detect.Metadata{})
	if out != in {
		t.Fatalf("a panicking engine must pass the text through unchanged, got %q", out)
	}
	if !res.Degraded || res.Err == nil {
		t.Error("the failure must be reported even though it did not block")
	}
}

type erroringEngine struct{}

func (erroringEngine) Name() string                      { return "errors" }
func (erroringEngine) Capabilities() detect.Capabilities { return detect.Capabilities{} }
func (erroringEngine) Scan(context.Context, []byte, detect.Metadata) ([]detect.Finding, error) {
	return nil, errors.New("engine failed")
}

func TestProcess_FailsOpenOnError(t *testing.T) {
	p, _ := New(erroringEngine{})
	const in = "texto qualquer"
	out, res := p.Process(context.Background(), in, detect.Metadata{})
	if out != in || !res.Degraded {
		t.Errorf("expected pass-through and Degraded, got %q %+v", out, res)
	}
}

// A networked engine on this path is a broken session, not a slow scan.
type networkedEngine struct{ detect.Engine }

func (networkedEngine) Name() string { return "networked" }
func (networkedEngine) Capabilities() detect.Capabilities {
	return detect.Capabilities{RequiresNetwork: true}
}
func (networkedEngine) Scan(context.Context, []byte, detect.Metadata) ([]detect.Finding, error) {
	return nil, nil
}

func TestNew_RefusesNetworkedEngine(t *testing.T) {
	if _, err := New(networkedEngine{}); !errors.Is(err, ErrRequiresNetwork) {
		t.Fatalf("want ErrRequiresNetwork, got %v", err)
	}
}

func TestProcess_MaxInputPassesThroughRatherThanHolding(t *testing.T) {
	big := strings.Repeat("x", 100) + cpf
	out, res := proc(t, WithMaxInput(50)).Process(context.Background(), big, detect.Metadata{})
	if out != big {
		t.Error("oversized input should pass through unchanged")
	}
	if !res.Degraded {
		t.Error("exceeding the cap should be reported as degraded")
	}
}

func TestCopy_StreamsAndRedacts(t *testing.T) {
	var out bytes.Buffer
	res, err := proc(t).Copy(context.Background(), &out, strings.NewReader("cpf "+cpf), detect.Metadata{})
	if err != nil {
		t.Fatalf("Copy: %v", err)
	}
	if strings.Contains(out.String(), cpf) {
		t.Fatalf("the value survived: %s", out.String())
	}
	if !res.Redacted {
		t.Error("Redacted should be true")
	}
}

// The budget that decides whether the hook is usable at all.
func TestProcess_LatencyBudget(t *testing.T) {
	if testing.Short() {
		t.Skip("latency check skipped in short mode")
	}

	p := proc(t)
	// A tool result of the size an agent actually sees.
	text := strings.Repeat("arquivo de codigo com linhas normais aqui\n", 200) + "cpf " + cpf

	p.Process(context.Background(), text, detect.Metadata{}) // warm up

	const runs = 200
	durations := make([]time.Duration, runs)
	for i := range durations {
		start := time.Now()
		p.Process(context.Background(), text, detect.Metadata{})
		durations[i] = time.Since(start)
	}

	slowest := durations[0]
	for _, d := range durations {
		if d > slowest {
			slowest = d
		}
	}
	t.Logf("%d bytes, worst of %d runs: %v", len(text), runs, slowest)

	// Generous against CI hardware and the race detector; the regression it
	// guards against is an order of magnitude, not a few milliseconds.
	if slowest > 100*time.Millisecond {
		t.Errorf("worst case %v is far above the 10ms target for a hook", slowest)
	}
}
