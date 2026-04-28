package probes

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/brexhq/CrabTrap/internal/llm"
)

// newRunnerWithFixedScores wires a Runner to an httptest server that always
// returns the given per-probe per-token score map.
func newRunnerWithFixedScores(t *testing.T, specs []Spec, maxBody int, scores map[string][]float64) (*Runner, *httptest.Server) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(probeSuccessResponse(scores))
	}))
	c := NewClient(server.URL, "test-model", "", 5*time.Second, 32)
	return NewRunner(c, StaticSpecs(specs), maxBody), server
}

func TestRunner_NoTrip_AllBelowThreshold(t *testing.T) {
	r, server := newRunnerWithFixedScores(t,
		[]Spec{{Name: "exfiltration", Threshold: 0.8, Aggregation: "max"}},
		0,
		map[string][]float64{"exfiltration": {0.1, 0.2, 0.3}},
	)
	defer server.Close()

	result, err := r.Evaluate(context.Background(), "GET", "https://example.com", http.Header{}, "", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Tripped != "" {
		t.Errorf("expected no trip, got %q", result.Tripped)
	}
	if got := result.Scores["exfiltration"]; got != 0.3 {
		t.Errorf("expected aggregated score 0.3, got %v", got)
	}
}

func TestRunner_Trips_MaxAggregation(t *testing.T) {
	r, server := newRunnerWithFixedScores(t,
		[]Spec{{Name: "exfiltration", Threshold: 0.7, Aggregation: "max"}},
		0,
		map[string][]float64{"exfiltration": {0.1, 0.9, 0.3}},
	)
	defer server.Close()

	result, err := r.Evaluate(context.Background(), "POST", "https://example.com/api", http.Header{}, `{"data":"secret"}`, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Tripped != "exfiltration" {
		t.Errorf("expected trip on exfiltration, got %q", result.Tripped)
	}
	if result.Aggregation != "max" {
		t.Errorf("expected aggregation=max, got %q", result.Aggregation)
	}
	if got := result.Scores["exfiltration"]; got != 0.9 {
		t.Errorf("expected aggregated score 0.9, got %v", got)
	}
}

func TestRunner_MeanAggregation(t *testing.T) {
	r, server := newRunnerWithFixedScores(t,
		[]Spec{{Name: "jailbreak", Threshold: 0.5, Aggregation: "mean"}},
		0,
		map[string][]float64{"jailbreak": {0.4, 0.6, 0.8}}, // mean = 0.6, trips
	)
	defer server.Close()

	result, err := r.Evaluate(context.Background(), "GET", "https://example.com", http.Header{}, "", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Tripped != "jailbreak" {
		t.Errorf("expected trip on jailbreak, got %q", result.Tripped)
	}
	if got := result.Scores["jailbreak"]; got < 0.59 || got > 0.61 {
		t.Errorf("expected mean ≈ 0.6, got %v", got)
	}
}

func TestRunner_FirstTripWins(t *testing.T) {
	// jailbreak configured first; both trip, but Tripped should be jailbreak.
	r, server := newRunnerWithFixedScores(t,
		[]Spec{
			{Name: "jailbreak", Threshold: 0.5, Aggregation: "max"},
			{Name: "exfiltration", Threshold: 0.5, Aggregation: "max"},
		},
		0,
		map[string][]float64{
			"jailbreak":    {0.9},
			"exfiltration": {0.95},
		},
	)
	defer server.Close()

	result, err := r.Evaluate(context.Background(), "GET", "https://example.com", http.Header{}, "", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Tripped != "jailbreak" {
		t.Errorf("expected first configured probe to trip, got %q", result.Tripped)
	}
	if len(result.Scores) != 2 {
		t.Errorf("expected both probes' scores recorded, got %v", result.Scores)
	}
}

func TestRunner_EmptyScoreArray_NoTrip(t *testing.T) {
	r, server := newRunnerWithFixedScores(t,
		[]Spec{{Name: "exfiltration", Threshold: 0.1, Aggregation: "max"}},
		0,
		map[string][]float64{"exfiltration": {}},
	)
	defer server.Close()

	result, err := r.Evaluate(context.Background(), "GET", "https://example.com", http.Header{}, "", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Tripped != "" {
		t.Errorf("expected no trip for empty score array, got %q", result.Tripped)
	}
	if got := result.Scores["exfiltration"]; got != 0.0 {
		t.Errorf("expected score 0.0 for empty array, got %v", got)
	}
}

func TestRunner_MissingProbe_RecordsZero(t *testing.T) {
	r, server := newRunnerWithFixedScores(t,
		[]Spec{
			{Name: "exfiltration", Threshold: 0.5, Aggregation: "max"},
			{Name: "jailbreak", Threshold: 0.5, Aggregation: "max"},
		},
		0,
		map[string][]float64{"exfiltration": {0.3}}, // jailbreak absent
	)
	defer server.Close()

	result, err := r.Evaluate(context.Background(), "GET", "https://example.com", http.Header{}, "", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Tripped != "" {
		t.Errorf("expected no trip, got %q", result.Tripped)
	}
	if got, ok := result.Scores["jailbreak"]; !ok || got != 0.0 {
		t.Errorf("missing probe should record as 0.0, got %v (ok=%v)", got, ok)
	}
}

func TestRunner_DefaultAggregationIsMax(t *testing.T) {
	r, server := newRunnerWithFixedScores(t,
		[]Spec{{Name: "exfiltration", Threshold: 0.7}}, // no Aggregation set
		0,
		map[string][]float64{"exfiltration": {0.1, 0.9, 0.3}},
	)
	defer server.Close()

	result, err := r.Evaluate(context.Background(), "GET", "https://example.com", http.Header{}, "", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Tripped != "exfiltration" {
		t.Errorf("expected trip, got %q", result.Tripped)
	}
	if result.Aggregation != "max" {
		t.Errorf("expected default aggregation=max, got %q", result.Aggregation)
	}
}

func TestRunner_AllClear_WhenEverySpecHasClearThresholdAndAllBelow(t *testing.T) {
	r, server := newRunnerWithFixedScores(t,
		[]Spec{
			{Name: "exfiltration", Threshold: 0.8, ClearThreshold: 0.1, Aggregation: "max"},
			{Name: "jailbreak", Threshold: 0.7, ClearThreshold: 0.1, Aggregation: "max"},
		},
		0,
		map[string][]float64{
			"exfiltration": {0.02, 0.05},
			"jailbreak":    {0.01, 0.08},
		},
	)
	defer server.Close()

	result, err := r.Evaluate(context.Background(), "GET", "https://example.com", http.Header{}, "", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Tripped != "" {
		t.Errorf("expected no trip, got %q", result.Tripped)
	}
	if !result.AllClear {
		t.Errorf("expected AllClear=true when all scores <= clear_threshold, got false (scores=%v)", result.Scores)
	}
}

func TestRunner_AllClear_False_WhenAnySpecLacksClearThreshold(t *testing.T) {
	r, server := newRunnerWithFixedScores(t,
		[]Spec{
			{Name: "exfiltration", Threshold: 0.8, ClearThreshold: 0.1, Aggregation: "max"},
			{Name: "jailbreak", Threshold: 0.7, Aggregation: "max"}, // ClearThreshold unset
		},
		0,
		map[string][]float64{
			"exfiltration": {0.02},
			"jailbreak":    {0.01},
		},
	)
	defer server.Close()

	result, err := r.Evaluate(context.Background(), "GET", "https://example.com", http.Header{}, "", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.AllClear {
		t.Error("expected AllClear=false because one spec has no clear threshold (opt-in per probe)")
	}
}

func TestRunner_AllClear_False_WhenOneScoreExceedsClearThreshold(t *testing.T) {
	r, server := newRunnerWithFixedScores(t,
		[]Spec{
			{Name: "exfiltration", Threshold: 0.8, ClearThreshold: 0.1, Aggregation: "max"},
			{Name: "jailbreak", Threshold: 0.7, ClearThreshold: 0.1, Aggregation: "max"},
		},
		0,
		map[string][]float64{
			"exfiltration": {0.02},
			"jailbreak":    {0.25}, // above clear but below fire: the gray zone
		},
	)
	defer server.Close()

	result, err := r.Evaluate(context.Background(), "GET", "https://example.com", http.Header{}, "", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Tripped != "" {
		t.Errorf("expected no trip (0.25 < 0.7), got %q", result.Tripped)
	}
	if result.AllClear {
		t.Error("expected AllClear=false when one score is in the gray zone")
	}
}

func TestRunner_AllClear_False_WhenProbeTripped(t *testing.T) {
	// A tripped probe must never be reported as AllClear, even if the numbers
	// happened to line up (defence in depth against bad calibration).
	r, server := newRunnerWithFixedScores(t,
		[]Spec{
			{Name: "exfiltration", Threshold: 0.5, ClearThreshold: 0.1, Aggregation: "max"},
		},
		0,
		map[string][]float64{"exfiltration": {0.9}},
	)
	defer server.Close()

	result, err := r.Evaluate(context.Background(), "GET", "https://example.com", http.Header{}, "", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Tripped != "exfiltration" {
		t.Fatalf("expected trip, got %q", result.Tripped)
	}
	if result.AllClear {
		t.Error("expected AllClear=false when a probe is tripped")
	}
}

func TestRunner_GrayZoneEscalation_PicksFirstSpecWithJudgePolicy(t *testing.T) {
	// jailbreak (priority 0) is in its gray zone with a judge policy set;
	// exfiltration (priority 1) is also in its gray zone but has no policy.
	// We expect the first matching spec to win.
	r, server := newRunnerWithFixedScores(t,
		[]Spec{
			{Name: "jailbreak", Threshold: 0.8, ClearThreshold: 0.1, Aggregation: "max", JudgePolicyID: "policy-jb"},
			{Name: "exfiltration", Threshold: 0.8, ClearThreshold: 0.1, Aggregation: "max"},
		},
		0,
		map[string][]float64{
			"jailbreak":    {0.4}, // gray zone
			"exfiltration": {0.5}, // gray zone, no policy
		},
	)
	defer server.Close()

	result, err := r.Evaluate(context.Background(), "POST", "https://example.com/api", http.Header{}, `{"q":"x"}`, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Tripped != "" {
		t.Fatalf("expected no trip, got %q", result.Tripped)
	}
	if result.AllClear {
		t.Fatalf("expected gray zone, got AllClear=true")
	}
	if result.GrayZoneProbe != "jailbreak" {
		t.Errorf("GrayZoneProbe = %q, want jailbreak", result.GrayZoneProbe)
	}
	if result.GrayZonePolicyID != "policy-jb" {
		t.Errorf("GrayZonePolicyID = %q, want policy-jb", result.GrayZonePolicyID)
	}
}

func TestRunner_GrayZoneEscalation_SkipsSpecWithoutPolicy(t *testing.T) {
	// First spec has no policy; second has one but is also in its gray zone.
	// Second should win the escalation.
	r, server := newRunnerWithFixedScores(t,
		[]Spec{
			{Name: "exfiltration", Threshold: 0.8, ClearThreshold: 0.1, Aggregation: "max"},
			{Name: "jailbreak", Threshold: 0.8, ClearThreshold: 0.1, Aggregation: "max", JudgePolicyID: "policy-jb"},
		},
		0,
		map[string][]float64{
			"exfiltration": {0.4},
			"jailbreak":    {0.4},
		},
	)
	defer server.Close()

	result, err := r.Evaluate(context.Background(), "POST", "https://example.com/api", http.Header{}, "", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.GrayZoneProbe != "jailbreak" {
		t.Errorf("GrayZoneProbe = %q, want jailbreak", result.GrayZoneProbe)
	}
	if result.GrayZonePolicyID != "policy-jb" {
		t.Errorf("GrayZonePolicyID = %q, want policy-jb", result.GrayZonePolicyID)
	}
}

func TestRunner_GrayZoneEscalation_SkipsConfidentlyClearSpec(t *testing.T) {
	// jailbreak has a policy and a clear threshold; its score is below the
	// clear threshold so it's not in its own gray zone — escalation should
	// not pick it. exfiltration is in the gray zone with no policy. Result:
	// no escalation.
	r, server := newRunnerWithFixedScores(t,
		[]Spec{
			{Name: "jailbreak", Threshold: 0.8, ClearThreshold: 0.2, Aggregation: "max", JudgePolicyID: "policy-jb"},
			{Name: "exfiltration", Threshold: 0.8, ClearThreshold: 0.2, Aggregation: "max"},
		},
		0,
		map[string][]float64{
			"jailbreak":    {0.05}, // below clear — confidently OK
			"exfiltration": {0.5},  // gray zone, no policy
		},
	)
	defer server.Close()

	result, err := r.Evaluate(context.Background(), "POST", "https://example.com/api", http.Header{}, "", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.GrayZoneProbe != "" {
		t.Errorf("GrayZoneProbe = %q, expected empty (jailbreak is below clear)", result.GrayZoneProbe)
	}
	if result.GrayZonePolicyID != "" {
		t.Errorf("GrayZonePolicyID = %q, expected empty", result.GrayZonePolicyID)
	}
}

func TestRunner_GrayZoneEscalation_NoneSetWhenTripped(t *testing.T) {
	// When a probe trips, the runner returns DENY — gray-zone fields are
	// allowed to be set but should not influence behavior. Document the
	// observed value here so future refactors don't silently change it.
	r, server := newRunnerWithFixedScores(t,
		[]Spec{
			{Name: "jailbreak", Threshold: 0.5, ClearThreshold: 0.1, Aggregation: "max", JudgePolicyID: "policy-jb"},
		},
		0,
		map[string][]float64{"jailbreak": {0.9}}, // trips
	)
	defer server.Close()

	result, err := r.Evaluate(context.Background(), "GET", "https://example.com", http.Header{}, "", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Tripped != "jailbreak" {
		t.Fatalf("expected trip, got %q", result.Tripped)
	}
	// A tripped probe is not "in the gray zone" (score >= threshold), so
	// GrayZonePolicyID should be empty.
	if result.GrayZonePolicyID != "" {
		t.Errorf("GrayZonePolicyID = %q, expected empty when probe tripped", result.GrayZonePolicyID)
	}
}

func TestRunner_CircuitOpen_ReturnsFlagWithoutError(t *testing.T) {
	// Server always 500s; after 3 failures the breaker trips.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	c := NewClient(server.URL, "test-model", "", 1*time.Second, 32,
		llm.WithCircuitBreaker(3, 1*time.Hour),
	)
	r := NewRunner(c, StaticSpecs([]Spec{{Name: "exfiltration", Threshold: 0.5, Aggregation: "max"}}), 0)

	for i := 0; i < 3; i++ {
		// Pre-warm the breaker with real failing calls via the client directly.
		c.Complete(context.Background(), "sys", "user") //nolint:errcheck
	}
	if !c.IsOpen() {
		t.Fatal("precondition: expected circuit breaker to be open")
	}

	result, err := r.Evaluate(context.Background(), "GET", "https://example.com", http.Header{}, "", "")
	if err != nil {
		t.Fatalf("Evaluate should swallow circuit-open; got err %v", err)
	}
	if !result.CircuitOpen {
		t.Error("expected result.CircuitOpen=true")
	}
	if result.Tripped != "" {
		t.Error("expected no trip when circuit is open")
	}
}

func TestRunner_HTTPError_ReturnsError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer server.Close()

	c := NewClient(server.URL, "test-model", "", 1*time.Second, 32)
	r := NewRunner(c, StaticSpecs([]Spec{{Name: "exfiltration", Threshold: 0.5}}), 0)

	_, err := r.Evaluate(context.Background(), "GET", "https://example.com", http.Header{}, "", "")
	if err == nil {
		t.Fatal("expected error on HTTP 502")
	}
	if !strings.Contains(err.Error(), "probe client complete failed") {
		t.Errorf("error should wrap client failure, got %v", err)
	}
}

func TestRunner_SendsExtractedChatContentNotHTTPWrapper(t *testing.T) {
	var capturedBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.Write(probeSuccessResponse(map[string][]float64{}))
	}))
	defer server.Close()

	c := NewClient(server.URL, "test-model", "", 5*time.Second, 32)
	// Provide a placeholder spec so the runner actually invokes probe-demo
	// and captures the body — this test only cares about the wire format.
	r := NewRunner(c, StaticSpecs([]Spec{{Name: "x", Threshold: 1.0}}), 0)

	headers := http.Header{}
	headers.Set("Content-Type", "application/json")
	reqBody := `{"model":"gpt-4","messages":[{"role":"user","content":"what is 2 plus 2"}]}`
	if _, err := r.Evaluate(context.Background(), "POST", "https://api.example.com/v1/chat/completions", headers, reqBody, ""); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var body struct {
		Messages []struct{ Role, Content string }
	}
	if err := json.Unmarshal(capturedBody, &body); err != nil {
		t.Fatalf("failed to parse body: %v", err)
	}
	if len(body.Messages) != 2 {
		t.Fatalf("expected 2 messages, got %d", len(body.Messages))
	}
	// User message must be the extracted chat content, not the HTTP wrapper.
	if body.Messages[1].Content != "what is 2 plus 2" {
		t.Errorf("user message = %q, want raw content", body.Messages[1].Content)
	}
	if strings.Contains(body.Messages[1].Content, "https://api.example.com") {
		t.Errorf("HTTP URL leaked into probe input: %s", body.Messages[1].Content)
	}
}

// TestRunner_ThreadsPolicyIDToSpecsProvider locks in the contract that
// Evaluate calls its SpecsProvider with the policyID passed in by the caller.
// This is the single seam that Phase 3 added; if anyone refactors the runner
// and accidentally drops the parameter, every per-policy probe attachment
// would silently revert to the global fallback.
func TestRunner_ThreadsPolicyIDToSpecsProvider(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(probeSuccessResponse(map[string][]float64{}))
	}))
	defer server.Close()

	c := NewClient(server.URL, "test-model", "", 5*time.Second, 32)

	var seen []string
	specsProvider := func(_ context.Context, policyID string) ([]Spec, error) {
		seen = append(seen, policyID)
		return []Spec{{Name: "x", Threshold: 1.0}}, nil
	}
	r := NewRunner(c, specsProvider, 0)

	if _, err := r.Evaluate(context.Background(), "GET", "https://example.com", http.Header{}, "", "llmpol_abc"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := r.Evaluate(context.Background(), "GET", "https://example.com", http.Header{}, "", ""); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(seen) != 2 {
		t.Fatalf("specs provider called %d times, want 2", len(seen))
	}
	if seen[0] != "llmpol_abc" {
		t.Errorf("first call policyID = %q, want llmpol_abc", seen[0])
	}
	if seen[1] != "" {
		t.Errorf("second call policyID = %q, want empty (global fallback)", seen[1])
	}
}

func TestExtractProbeInput(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{"openai string content", `{"messages":[{"role":"user","content":"hello"}]}`, "hello"},
		{"system message skipped", `{"messages":[{"role":"system","content":"be helpful"},{"role":"user","content":"ping"}]}`, "ping"},
		{"tail from last user only", `{"messages":[{"role":"user","content":"first"},{"role":"assistant","content":"reply"},{"role":"user","content":"latest"}]}`, "latest"},
		{"includes assistant tool_call and tool result after last user",
			`{"messages":[{"role":"user","content":"search btc"},{"role":"assistant","content":null,"tool_calls":[{"function":{"name":"search","arguments":"q=btc"}}]},{"role":"tool","content":"BTC=$50k"}]}`,
			"search btc\n[tool_call name=search arguments=q=btc]\nBTC=$50k"},
		{"tool activity expands tail to full conversation",
			`{"messages":[{"role":"user","content":"find me investments"},{"role":"assistant","content":null,"tool_calls":[{"function":{"name":"search","arguments":"stocks"}}]},{"role":"tool","content":"AAPL"},{"role":"user","content":"go ahead"}]}`,
			"find me investments\n[tool_call name=search arguments=stocks]\nAAPL\ngo ahead"},
		{"anthropic content parts", `{"messages":[{"role":"user","content":[{"type":"text","text":"part one"},{"type":"text","text":"part two"}]}]}`, "part one\npart two"},
		{"non-chat body fallback", `{"query":"SELECT 1"}`, `{"query":"SELECT 1"}`},
		{"invalid json fallback", `not json at all`, `not json at all`},
		{"empty body", ``, ``},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := extractProbeInput(tc.body, 0)
			if got != tc.want {
				t.Errorf("extractProbeInput(%q) = %q, want %q", tc.body, got, tc.want)
			}
		})
	}
}

func TestExtractProbeInput_CapsOversizedContent(t *testing.T) {
	long := strings.Repeat("a", 10000)
	body := `{"messages":[{"role":"user","content":"` + long + `"}]}`
	got := extractProbeInput(body, 100)
	if len(got) != 100 {
		t.Errorf("len = %d, want 100", len(got))
	}
}

func TestAggregate(t *testing.T) {
	cases := []struct {
		name   string
		tokens []float64
		method string
		want   float64
	}{
		{"empty max", nil, "max", 0.0},
		{"empty mean", []float64{}, "mean", 0.0},
		{"single max", []float64{0.7}, "max", 0.7},
		{"max picks highest", []float64{0.1, 0.9, 0.3}, "max", 0.9},
		{"mean averages", []float64{0.2, 0.4, 0.6}, "mean", 0.4},
		{"unknown method falls back to max", []float64{0.1, 0.5, 0.3}, "bogus", 0.5},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := aggregate(tc.tokens, tc.method)
			if got < tc.want-1e-9 || got > tc.want+1e-9 {
				t.Errorf("aggregate(%v, %q) = %v, want %v", tc.tokens, tc.method, got, tc.want)
			}
		})
	}
}
