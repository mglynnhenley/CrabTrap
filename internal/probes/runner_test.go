package probes

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/brexhq/CrabTrap/internal/config"
	"github.com/brexhq/CrabTrap/internal/llm"
)

// scoreServer returns an httptest.Server that emits an SSE analyze stream.
// The peakScore is placed in probe_probs so the runner's max-aggregator
// resolves to that exact value. The optional `byPeak` map lets a test inject
// different peaks for different specs by inspecting the request's `text`.
//
// The Modal probe service is single-purpose (one probe per endpoint), so the
// wire payload has no probe_name. We still need per-spec score control in
// tests, hence keying off the body text via a key-fn.
func scoreServer(t *testing.T, peakScore float64) *httptest.Server {
	t.Helper()
	return scoreServerByText(t, func(_ string) (float64, bool) { return peakScore, true })
}

// scoreServerByText is like scoreServer but lets the caller derive the peak
// score from the request's `text` body. Returning ok=false makes the server
// respond 404 (used by tests that assert on "unknown" inputs).
func scoreServerByText(t *testing.T, peakFn func(text string) (float64, bool)) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Text      string `json:"text"`
			BatchSize int    `json:"batch_size"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		peak, ok := peakFn(req.Text)
		if !ok {
			http.Error(w, "unknown", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		flusher, _ := w.(http.Flusher)
		// Emit a status event, an analyze_start, then a single analyze_done
		// with probe_probs containing the peak. Real Modal output streams
		// many analyze_batch events too; the client ignores everything until
		// analyze_done so we don't bother emitting them.
		fmt.Fprint(w, "event: status\ndata: {\"type\":\"status\",\"message\":\"loading\"}\n\n")
		fmt.Fprint(w, "event: analyze_start\ndata: {\"type\":\"analyze_start\",\"token_count\":3}\n\n")
		if flusher != nil {
			flusher.Flush()
		}
		probs := []float64{0.0, peak / 2, peak}
		payload, _ := json.Marshal(map[string]any{
			"type":        "analyze_done",
			"probe_probs": probs,
		})
		fmt.Fprintf(w, "event: analyze_done\ndata: %s\n\n", string(payload))
	}))
}

func newRunnerForTest(t *testing.T, srv *httptest.Server, opts ...llm.ResilienceOption) *Runner {
	t.Helper()
	cfg := config.ProbesConfig{
		Enabled:      true,
		Endpoint:     srv.URL,
		APIKey:       "test-key",
		BatchSize:    8,
		Timeout:      2 * time.Second,
		MaxBodyBytes: 32 * 1024,
	}
	r, err := NewRunner(cfg, opts...)
	if err != nil {
		t.Fatalf("NewRunner: %v", err)
	}
	return r
}

func TestEvaluate_TripDeniesAndScoresPopulated(t *testing.T) {
	srv := scoreServer(t, 0.95)
	defer srv.Close()
	r := newRunnerForTest(t, srv)

	res := r.Evaluate(context.Background(),
		[]Spec{{Name: "hallucination", Threshold: 0.8, ClearThreshold: 0.3}},
		"POST", "https://api.example.com/x", []byte(`{"q":"hi"}`),
	)
	if res.Tripped == nil {
		t.Fatal("expected Tripped, got nil")
	}
	if res.Tripped.Name != "hallucination" || res.Tripped.Score != 0.95 || res.Tripped.Threshold != 0.8 {
		t.Errorf("Tripped = %+v", res.Tripped)
	}
	if res.AllClear {
		t.Error("AllClear must be false when a probe trips")
	}
	if res.SkippedReason != "" {
		t.Errorf("SkippedReason = %q", res.SkippedReason)
	}
}

func TestEvaluate_AllClearAllowsWithoutJudge(t *testing.T) {
	srv := scoreServer(t, 0.10)
	defer srv.Close()
	r := newRunnerForTest(t, srv)

	res := r.Evaluate(context.Background(),
		[]Spec{{Name: "hallucination", Threshold: 0.8, ClearThreshold: 0.3}},
		"GET", "https://api.example.com/x", nil,
	)
	if res.Tripped != nil {
		t.Errorf("unexpected Tripped: %+v", res.Tripped)
	}
	if !res.AllClear {
		t.Error("expected AllClear=true")
	}
}

func TestEvaluate_GrayZoneFallsThroughToJudge(t *testing.T) {
	srv := scoreServer(t, 0.50)
	defer srv.Close()
	r := newRunnerForTest(t, srv)

	res := r.Evaluate(context.Background(),
		[]Spec{{Name: "hallucination", Threshold: 0.8, ClearThreshold: 0.3}},
		"GET", "https://api.example.com/x", nil,
	)
	if res.Tripped != nil {
		t.Errorf("unexpected Tripped: %+v", res.Tripped)
	}
	if res.AllClear {
		t.Error("AllClear must be false in gray zone")
	}
	if res.SkippedReason != "" {
		t.Errorf("SkippedReason = %q", res.SkippedReason)
	}
}

// TestEvaluate_TripWinsOverLenientClear locks in the unconditional precedence:
// when one spec trips, AllClear is forced false even if other specs would be
// below their own clear thresholds.
//
// Note: the Modal probe service is single-purpose, so all specs see the same
// score. We still get coverage of the precedence rule by using two specs with
// different thresholds against the same peak.
func TestEvaluate_TripWinsOverLenientClear(t *testing.T) {
	srv := scoreServer(t, 0.95)
	defer srv.Close()
	r := newRunnerForTest(t, srv)

	res := r.Evaluate(context.Background(),
		[]Spec{
			// Strict: trips at 0.95 ≥ 0.8.
			{Name: "strict", Threshold: 0.8, ClearThreshold: 0.3},
			// Lenient: 0.95 < threshold 0.99 (no trip) and 0.95 < clear 0.99
			// (would contribute to AllClear if alone).
			{Name: "lenient", Threshold: 0.99, ClearThreshold: 0.99},
		},
		"POST", "https://api.example.com/x", []byte(`{}`),
	)
	if res.Tripped == nil || res.Tripped.Name != "strict" {
		t.Errorf("expected Tripped=strict, got %+v", res.Tripped)
	}
	if res.AllClear {
		t.Error("AllClear must remain false when any probe trips")
	}
}

func TestEvaluate_TransportErrorFallsThrough(t *testing.T) {
	// Server that closes the connection immediately.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, _, _ := w.(http.Hijacker).Hijack()
		conn.Close()
	}))
	defer srv.Close()
	r := newRunnerForTest(t, srv)

	res := r.Evaluate(context.Background(),
		[]Spec{{Name: "injection", Threshold: 0.8, ClearThreshold: 0.3}},
		"GET", "https://api.example.com/x", nil,
	)
	if res.Tripped != nil {
		t.Errorf("unexpected Tripped: %+v", res.Tripped)
	}
	if res.AllClear {
		t.Error("AllClear must be false on transport error")
	}
	if res.SkippedReason == "" {
		t.Error("expected non-empty SkippedReason on transport error")
	}
}

func TestEvaluate_CircuitBreakerShortCircuitsAfterFailures(t *testing.T) {
	// Server that always returns 500.
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()

	r := newRunnerForTest(t, srv,
		llm.WithCircuitBreaker(3, 10*time.Second),
	)

	specs := []Spec{{Name: "injection", Threshold: 0.8, ClearThreshold: 0.3}}

	// Exhaust the breaker.
	for i := 0; i < 3; i++ {
		res := r.Evaluate(context.Background(), specs, "GET", "https://x", nil)
		if res.SkippedReason == "" {
			t.Fatalf("call %d: expected skip, got %+v", i, res)
		}
	}

	priorHits := atomic.LoadInt32(&hits)
	res := r.Evaluate(context.Background(), specs, "GET", "https://x", nil)
	if res.SkippedReason != "circuit_open" {
		t.Errorf("expected circuit_open, got %q", res.SkippedReason)
	}
	if atomic.LoadInt32(&hits) != priorHits {
		t.Error("circuit_open call must not hit the server")
	}
}

func TestEvaluate_EmptySpecsReturnsZeroResult(t *testing.T) {
	srv := scoreServer(t, 0.0)
	defer srv.Close()
	r := newRunnerForTest(t, srv)

	res := r.Evaluate(context.Background(), nil, "GET", "https://x", nil)
	if res.Tripped != nil || res.AllClear || res.SkippedReason != "" || len(res.Scores) != 0 {
		t.Errorf("expected zero Result for empty specs, got %+v", res)
	}
}
