package probes

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/brexhq/CrabTrap/internal/config"
	"github.com/brexhq/CrabTrap/internal/llm"
)

// Spec is the runtime shape consumed by Evaluate. It is converted from a
// policy's []types.PolicyProbe at call time — the runner is stateless about
// which probes attach to which policy.
type Spec struct {
	Name           string
	Threshold      float64 // score >= threshold → DENY
	ClearThreshold float64 // score <  clear_threshold → contributes to ALLOW
}

// Trip describes the probe that fired the DENY short-circuit. When non-nil on
// Result, the request must be denied and the judge skipped.
type Trip struct {
	Name      string
	Score     float64
	Threshold float64
}

// Result summarises one probe-tier evaluation.
//
// Precedence: Tripped is checked first. If any spec scored >= its Threshold,
// Tripped is set and AllClear is forced false regardless of how the other
// specs scored. AllClear is only true when no spec tripped AND every spec
// scored < its ClearThreshold.
type Result struct {
	Tripped       *Trip
	AllClear      bool
	Scores        map[string]float64
	DurationMs    int
	SkippedReason string // non-empty → caller must fall through to judge
}

// Runner drives one probe-service evaluation per request.
type Runner struct {
	client  *Client
	timeout time.Duration
	maxBody int
	enabled bool

	*llm.Resilience
}

// NewRunner constructs a Runner from the YAML probes config. It does not
// validate connectivity to the probe service.
func NewRunner(cfg config.ProbesConfig, opts ...llm.ResilienceOption) (*Runner, error) {
	if !cfg.Enabled {
		return nil, fmt.Errorf("probes runner created with Enabled=false")
	}
	if cfg.Endpoint == "" {
		return nil, fmt.Errorf("probes config missing endpoint")
	}

	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	maxBody := cfg.MaxBodyBytes
	if maxBody <= 0 {
		maxBody = 32 * 1024
	}
	batchSize := cfg.BatchSize
	if batchSize <= 0 {
		batchSize = 8
	}

	return &Runner{
		client:     NewClient(cfg.Endpoint, cfg.APIKey, batchSize),
		timeout:    timeout,
		maxBody:    maxBody,
		enabled:    true,
		Resilience: llm.NewResilience(opts...),
	}, nil
}

// Evaluate runs the given specs in parallel against the request. Specs come
// from the policy currently in context. Empty specs → returns an empty Result
// (no-op). Never returns error: failures populate SkippedReason and the caller
// must fall through to the judge.
func (r *Runner) Evaluate(ctx context.Context, specs []Spec, method, url string, body []byte) Result {
	if len(specs) == 0 {
		return Result{}
	}

	start := time.Now()

	if err := r.Acquire(ctx, "probes"); err != nil {
		return Result{
			DurationMs:    int(time.Since(start).Milliseconds()),
			SkippedReason: classifySkipReason(err),
		}
	}
	defer r.Release()

	callCtx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	prompt := buildPrompt(method, url, body, r.maxBody)

	type probeResult struct {
		name  string
		score float64
		err   error
	}

	out := make(chan probeResult, len(specs))
	var wg sync.WaitGroup
	for _, spec := range specs {
		wg.Add(1)
		s := spec
		go func() {
			defer wg.Done()
			score, err := r.client.Score(callCtx, s.Name, prompt)
			out <- probeResult{name: s.Name, score: score, err: err}
		}()
	}
	wg.Wait()
	close(out)

	scores := make(map[string]float64, len(specs))
	var firstErr error
	for pr := range out {
		if pr.err != nil {
			if firstErr == nil {
				firstErr = pr.err
			}
			continue
		}
		scores[pr.name] = pr.score
	}

	durationMs := int(time.Since(start).Milliseconds())

	if firstErr != nil {
		// Partial coverage is worse than none: any failure marks the whole
		// evaluation skipped and the caller falls through to the judge.
		r.RecordFailure()
		return Result{
			Scores:        scores,
			DurationMs:    durationMs,
			SkippedReason: classifySkipReason(firstErr),
		}
	}
	r.RecordSuccess()

	// Precedence: a tripped probe trumps any clear signal.
	var tripped *Trip
	allClear := true
	for _, s := range specs {
		score := scores[s.Name]
		if score >= s.Threshold {
			if tripped == nil || score > tripped.Score {
				tripped = &Trip{Name: s.Name, Score: score, Threshold: s.Threshold}
			}
		}
		if score >= s.ClearThreshold {
			allClear = false
		}
	}

	return Result{
		Tripped:    tripped,
		AllClear:   tripped == nil && allClear,
		Scores:     scores,
		DurationMs: durationMs,
	}
}

// classifySkipReason maps an error from the client or resilience layer to a
// short tag suitable for logging and audit-log skip_reason.
func classifySkipReason(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "circuit breaker open"):
		return "circuit_open"
	case strings.Contains(msg, "context deadline exceeded"), strings.Contains(msg, "Client.Timeout"):
		return "timeout"
	case strings.Contains(msg, "transport:"):
		return "transport: " + truncate(msg, 200)
	case strings.Contains(msg, "bad_response"):
		return "bad_response: " + truncate(msg, 200)
	default:
		return truncate(msg, 200)
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// buildPrompt assembles the probe input from the request method, URL, and a
// truncated body. Headers are deliberately excluded — they may contain
// Authorization tokens we don't want forwarded to a third-party service.
func buildPrompt(method, url string, body []byte, maxBody int) string {
	var b strings.Builder
	b.WriteString(method)
	b.WriteString(" ")
	b.WriteString(url)
	b.WriteString("\n\n")
	if len(body) > maxBody {
		b.Write(body[:maxBody])
		b.WriteString("…[truncated]")
	} else {
		b.Write(body)
	}
	return b.String()
}
