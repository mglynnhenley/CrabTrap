package approval

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/brexhq/CrabTrap/internal/judge"
	"github.com/brexhq/CrabTrap/internal/llm"
	"github.com/brexhq/CrabTrap/internal/probes"
	"github.com/brexhq/CrabTrap/pkg/types"
)

// probeResponseBody builds an OpenAI-compatible chat completion with the
// given scores map. Matches backend/api/schemas.py:ChatCompletion.
func probeResponseBody(scores map[string][]float64) []byte {
	resp := map[string]interface{}{
		"id":      "chatcmpl-test",
		"object":  "chat.completion",
		"created": 1700000000,
		"model":   "test-model",
		"choices": []map[string]interface{}{{
			"index":         0,
			"message":       map[string]interface{}{"role": "assistant", "content": "..."},
			"finish_reason": "stop",
		}},
		"usage": map[string]int{
			"prompt_tokens":     10,
			"completion_tokens": 3,
			"total_tokens":      13,
		},
		"scores": scores,
	}
	b, _ := json.Marshal(resp)
	return b
}

// newProbeRunnerServer returns a runner whose probe-demo backend is an
// httptest.Server returning the fixed scores map. Caller must Close() the
// returned server.
func newProbeRunnerServer(t *testing.T, specs []probes.Spec, scores map[string][]float64) (*probes.Runner, *httptest.Server) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(probeResponseBody(scores))
	}))
	client := probes.NewClient(server.URL, "test-model", "", 5*time.Second, 32)
	return probes.NewRunner(client, probes.StaticSpecs(specs), 0), server
}

// newProbeRunnerErrorServer returns a runner whose server always returns 500.
func newProbeRunnerErrorServer(t *testing.T, specs []probes.Spec) (*probes.Runner, *httptest.Server) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	client := probes.NewClient(server.URL, "test-model", "", 1*time.Second, 32)
	return probes.NewRunner(client, probes.StaticSpecs(specs), 0), server
}

// --- Matrix cells ---

// Cell: mode=passthrough × probes=off. Should hit the fast path.
func TestProbes_Passthrough_ProbesOff_ReturnsPassthroughAllow(t *testing.T) {
	m := NewManager()
	m.SetMode("passthrough")

	req, _ := http.NewRequest("GET", "https://example.com", nil)
	decision, body, err := m.CheckApproval(context.Background(), req, "req1", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.Decision != types.DecisionAllow || decision.ApprovedBy != "passthrough" {
		t.Errorf("expected passthrough ALLOW, got %+v", decision)
	}
	if body != nil {
		t.Error("passthrough fast path should not read body")
	}
	if decision.ProbeScores != nil {
		t.Error("probe fields should be unset when probes are off")
	}
}

// Cell: mode=passthrough × probes=on (under threshold). Probes approve.
func TestProbes_Passthrough_ProbesUnderThreshold_AllowsViaProbes(t *testing.T) {
	m := NewManager()
	m.SetMode("passthrough")

	runner, server := newProbeRunnerServer(t,
		[]probes.Spec{{Name: "exfiltration", Threshold: 0.8, Aggregation: "max"}},
		map[string][]float64{"exfiltration": {0.1, 0.2}},
	)
	defer server.Close()
	m.SetProbeRunner(runner)

	req, _ := http.NewRequest("GET", "https://example.com", nil)
	decision, _, err := m.CheckApproval(context.Background(), req, "req2", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.Decision != types.DecisionAllow {
		t.Errorf("expected ALLOW, got %v", decision.Decision)
	}
	if decision.ApprovedBy != "probes" {
		t.Errorf("expected approvedBy=probes, got %q", decision.ApprovedBy)
	}
	if decision.Channel != "probe" {
		t.Errorf("expected channel=probe, got %q", decision.Channel)
	}
	if decision.ProbeScores["exfiltration"] != 0.2 {
		t.Errorf("expected aggregated score 0.2, got %v", decision.ProbeScores)
	}
}

// Cell: mode=passthrough × probes=on (over threshold). Probes DENY.
func TestProbes_Passthrough_ProbesOverThreshold_Denies(t *testing.T) {
	m := NewManager()
	m.SetMode("passthrough")

	runner, server := newProbeRunnerServer(t,
		[]probes.Spec{{Name: "exfiltration", Threshold: 0.5, Aggregation: "max"}},
		map[string][]float64{"exfiltration": {0.1, 0.9}},
	)
	defer server.Close()
	m.SetProbeRunner(runner)

	req, _ := http.NewRequest("POST", "https://example.com/steal", bytes.NewReader([]byte(`{"x":1}`)))
	decision, _, err := m.CheckApproval(context.Background(), req, "req3", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.Decision != types.DecisionDeny {
		t.Errorf("expected DENY, got %v", decision.Decision)
	}
	if decision.ApprovedBy != "probe:exfiltration" {
		t.Errorf("expected approvedBy=probe:exfiltration, got %q", decision.ApprovedBy)
	}
	if decision.Channel != "probe" {
		t.Errorf("expected channel=probe, got %q", decision.Channel)
	}
	if decision.ProbeTripped != "exfiltration" {
		t.Errorf("expected ProbeTripped=exfiltration, got %q", decision.ProbeTripped)
	}
	if !strings.Contains(decision.Reason, "tripped") {
		t.Errorf("reason should describe the trip: %q", decision.Reason)
	}
}

// Cell: mode=passthrough × probes=on (error). Probe failure non-fatal,
// passthrough ALLOW with probe error logged.
func TestProbes_Passthrough_ProbeError_StillAllows(t *testing.T) {
	m := NewManager()
	m.SetMode("passthrough")

	runner, server := newProbeRunnerErrorServer(t,
		[]probes.Spec{{Name: "exfiltration", Threshold: 0.5, Aggregation: "max"}},
	)
	defer server.Close()
	m.SetProbeRunner(runner)

	req, _ := http.NewRequest("GET", "https://example.com", nil)
	decision, _, err := m.CheckApproval(context.Background(), req, "req4", nil)
	if err != nil {
		t.Fatalf("probe errors should be non-fatal, got err %v", err)
	}
	if decision.Decision != types.DecisionAllow {
		t.Errorf("expected ALLOW (probe error, passthrough mode), got %v", decision.Decision)
	}
	if decision.ApprovedBy != "passthrough" {
		t.Errorf("probe error should fall back to passthrough, got approvedBy=%q", decision.ApprovedBy)
	}
}

// Cell: mode=llm × probes=off. Regression check — judge decides alone.
func TestProbes_LLM_ProbesOff_JudgeAllow(t *testing.T) {
	m := newLLMManager(t, allowJudge(), "deny")

	req, _ := http.NewRequest("GET", "https://example.com", nil)
	decision, _, err := m.CheckApproval(policyCtx("policy"), req, "req5", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.Decision != types.DecisionAllow || decision.ApprovedBy != "llm" {
		t.Errorf("expected llm ALLOW, got %+v", decision)
	}
	if decision.ProbeScores != nil {
		t.Error("probe fields should be unset when probes are off")
	}
}

// Cell: mode=llm × probes=on, probe under threshold, judge ALLOW.
// Judge's ALLOW stands and probe audit fields populated.
func TestProbes_LLM_ProbesUnderThreshold_JudgeAllowStands(t *testing.T) {
	m := newLLMManager(t, allowJudge(), "deny")
	runner, server := newProbeRunnerServer(t,
		[]probes.Spec{{Name: "jailbreak", Threshold: 0.8, Aggregation: "max"}},
		map[string][]float64{"jailbreak": {0.1}},
	)
	defer server.Close()
	m.SetProbeRunner(runner)

	req, _ := http.NewRequest("POST", "https://example.com/api", bytes.NewReader([]byte(`{"k":"v"}`)))
	decision, _, err := m.CheckApproval(policyCtx("policy"), req, "req6", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.Decision != types.DecisionAllow || decision.ApprovedBy != "llm" {
		t.Errorf("expected judge ALLOW to stand, got %+v", decision)
	}
	if decision.ProbeScores["jailbreak"] != 0.1 {
		t.Errorf("expected probe score audit field, got %v", decision.ProbeScores)
	}
	if decision.ProbeTripped != "" {
		t.Errorf("expected no trip, got %q", decision.ProbeTripped)
	}
}

// Cell: mode=llm × probes=on, probe trip → DENY and the judge is NEVER
// invoked (the whole point of the probes-first flow). This replaces the
// earlier behaviour where probe+judge ran in parallel.
func TestProbes_LLM_ProbeTripSkipsJudgeAndDenies(t *testing.T) {
	var judgeCalls int
	m := newLLMManager(t, countingJudge("ALLOW", &judgeCalls), "deny")
	runner, server := newProbeRunnerServer(t,
		[]probes.Spec{{Name: "exfiltration", Threshold: 0.5, Aggregation: "max"}},
		map[string][]float64{"exfiltration": {0.95}},
	)
	defer server.Close()
	m.SetProbeRunner(runner)

	req, _ := http.NewRequest("GET", "https://example.com/x", nil)
	decision, _, err := m.CheckApproval(policyCtx("permissive policy"), req, "req7", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.Decision != types.DecisionDeny {
		t.Errorf("probe trip should DENY, got %v", decision.Decision)
	}
	if decision.ApprovedBy != "probe:exfiltration" {
		t.Errorf("expected approvedBy=probe:exfiltration, got %q", decision.ApprovedBy)
	}
	if judgeCalls != 0 {
		t.Errorf("judge must not be invoked when a probe trips, got %d calls", judgeCalls)
	}
	if decision.LLMResponse != nil {
		t.Error("LLMResponse should be nil when the judge was skipped")
	}
}

// Cell: mode=llm × probes=on, every probe at/below clear_threshold → ALLOW
// and the judge is NEVER invoked. This is the main cost-saving path for
// confidence-band gating.
func TestProbes_LLM_AllClearSkipsJudgeAndAllows(t *testing.T) {
	var judgeCalls int
	m := newLLMManager(t, countingJudge("DENY", &judgeCalls), "deny") // judge would DENY if called
	runner, server := newProbeRunnerServer(t,
		[]probes.Spec{
			{Name: "exfiltration", Threshold: 0.8, ClearThreshold: 0.1, Aggregation: "max"},
			{Name: "jailbreak", Threshold: 0.7, ClearThreshold: 0.1, Aggregation: "max"},
		},
		map[string][]float64{
			"exfiltration": {0.02, 0.05},
			"jailbreak":    {0.01, 0.09},
		},
	)
	defer server.Close()
	m.SetProbeRunner(runner)

	req, _ := http.NewRequest("GET", "https://example.com", nil)
	decision, _, err := m.CheckApproval(policyCtx("policy"), req, "req-allclear", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.Decision != types.DecisionAllow {
		t.Errorf("expected ALLOW on all-clear, got %v", decision.Decision)
	}
	if decision.ApprovedBy != "probe:all-clear" {
		t.Errorf("expected approvedBy=probe:all-clear, got %q", decision.ApprovedBy)
	}
	if decision.Channel != "probe" {
		t.Errorf("expected channel=probe, got %q", decision.Channel)
	}
	if judgeCalls != 0 {
		t.Errorf("judge must not be invoked when all probes are clear, got %d calls", judgeCalls)
	}
	if decision.LLMResponse != nil {
		t.Error("LLMResponse should be nil when the judge was skipped")
	}
	if decision.ProbeScores["exfiltration"] != 0.05 {
		t.Errorf("probe scores should be attached for audit, got %v", decision.ProbeScores)
	}
}

// Cell: mode=llm × probes=on, any probe in the gray zone (above its
// clear_threshold but below its fire threshold) → judge runs and decides.
func TestProbes_LLM_GrayZoneFallsThroughToJudge(t *testing.T) {
	var judgeCalls int
	m := newLLMManager(t, countingJudge("ALLOW", &judgeCalls), "deny")
	runner, server := newProbeRunnerServer(t,
		[]probes.Spec{
			{Name: "exfiltration", Threshold: 0.8, ClearThreshold: 0.1, Aggregation: "max"},
			{Name: "jailbreak", Threshold: 0.7, ClearThreshold: 0.1, Aggregation: "max"},
		},
		map[string][]float64{
			"exfiltration": {0.02},   // clear
			"jailbreak":    {0.3},    // gray (> 0.1, < 0.7)
		},
	)
	defer server.Close()
	m.SetProbeRunner(runner)

	req, _ := http.NewRequest("GET", "https://example.com", nil)
	decision, _, err := m.CheckApproval(policyCtx("policy"), req, "req-gray", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.Decision != types.DecisionAllow || decision.ApprovedBy != "llm" {
		t.Errorf("expected judge ALLOW in gray zone, got %+v", decision)
	}
	if judgeCalls != 1 {
		t.Errorf("expected judge invoked exactly once, got %d calls", judgeCalls)
	}
	if decision.ProbeScores["jailbreak"] != 0.3 {
		t.Errorf("probe scores should still be attached, got %v", decision.ProbeScores)
	}
}

// Cell: mode=llm × probes=on, no spec has clear_threshold set → AllClear
// never triggers; every non-tripped request goes to the judge (backward
// compat with operators who haven't opted into judge-skip).
func TestProbes_LLM_NoClearThreshold_AlwaysRunsJudge(t *testing.T) {
	var judgeCalls int
	m := newLLMManager(t, countingJudge("ALLOW", &judgeCalls), "deny")
	runner, server := newProbeRunnerServer(t,
		// Threshold 0.8, no ClearThreshold. Scores way below 0.8 but AllClear
		// must stay false because the operator hasn't opted in.
		[]probes.Spec{{Name: "exfiltration", Threshold: 0.8, Aggregation: "max"}},
		map[string][]float64{"exfiltration": {0.01}},
	)
	defer server.Close()
	m.SetProbeRunner(runner)

	req, _ := http.NewRequest("GET", "https://example.com", nil)
	decision, _, err := m.CheckApproval(policyCtx("policy"), req, "req-noclear", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.Decision != types.DecisionAllow || decision.ApprovedBy != "llm" {
		t.Errorf("expected judge ALLOW when no clear_threshold configured, got %+v", decision)
	}
	if judgeCalls != 1 {
		t.Errorf("judge must run when no probe has clear_threshold, got %d calls", judgeCalls)
	}
}

// Cell: mode=llm × probes=on, probe error, judge ALLOW.
// Probe error falls through; judge ALLOW stands.
func TestProbes_LLM_ProbeError_JudgeAllowStands(t *testing.T) {
	m := newLLMManager(t, allowJudge(), "deny")
	runner, server := newProbeRunnerErrorServer(t,
		[]probes.Spec{{Name: "exfiltration", Threshold: 0.5, Aggregation: "max"}},
	)
	defer server.Close()
	m.SetProbeRunner(runner)

	req, _ := http.NewRequest("GET", "https://example.com", nil)
	decision, _, err := m.CheckApproval(policyCtx("policy"), req, "req8", nil)
	if err != nil {
		t.Fatalf("probe errors should be non-fatal, got err %v", err)
	}
	if decision.Decision != types.DecisionAllow || decision.ApprovedBy != "llm" {
		t.Errorf("expected judge ALLOW to stand when probe errors, got %+v", decision)
	}
}

// Cell: mode=llm × probes=on, judge DENY + probes pass → judge DENY stands.
func TestProbes_LLM_JudgeDenyWithProbesPass(t *testing.T) {
	m := newLLMManager(t, denyJudge(), "deny")
	runner, server := newProbeRunnerServer(t,
		[]probes.Spec{{Name: "jailbreak", Threshold: 0.8, Aggregation: "max"}},
		map[string][]float64{"jailbreak": {0.1}},
	)
	defer server.Close()
	m.SetProbeRunner(runner)

	req, _ := http.NewRequest("GET", "https://example.com", nil)
	decision, _, err := m.CheckApproval(policyCtx("strict policy"), req, "req9", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.Decision != types.DecisionDeny || decision.ApprovedBy != "llm" {
		t.Errorf("expected judge DENY to stand, got %+v", decision)
	}
	if decision.ProbeScores["jailbreak"] != 0.1 {
		t.Errorf("probe scores should still be recorded for audit, got %v", decision.ProbeScores)
	}
}

// Cell: static rule deny short-circuits before probes or judge run.
func TestProbes_StaticRuleDenyShortCircuits(t *testing.T) {
	m := newLLMManager(t, allowJudge(), "deny")
	// If probes ran, this would trip and return DENY via probe. But static rule
	// deny must short-circuit first — observed via channel=llm (not probe).
	runner, server := newProbeRunnerServer(t,
		[]probes.Spec{{Name: "x", Threshold: 0.1, Aggregation: "max"}},
		map[string][]float64{"x": {0.9}},
	)
	defer server.Close()
	m.SetProbeRunner(runner)

	policy := &types.LLMPolicy{
		ID:     "llmpol_static",
		Prompt: "policy",
		StaticRules: []types.StaticRule{
			{URLPattern: "https://blocked.example.com", Action: "deny", MatchType: "prefix"},
		},
	}
	ctx := context.WithValue(context.Background(), ContextKeyLLMPolicy, policy)

	req, _ := http.NewRequest("GET", "https://blocked.example.com/x", nil)
	decision, _, err := m.CheckApproval(ctx, req, "req10", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.ApprovedBy != "llm-static-rule" {
		t.Errorf("expected static-rule short-circuit, got approvedBy=%q", decision.ApprovedBy)
	}
	if decision.Decision != types.DecisionDeny {
		t.Errorf("expected DENY, got %v", decision.Decision)
	}
	// Probe fields should not be set — probes never ran.
	if decision.ProbeScores != nil {
		t.Error("static-rule short-circuit should skip probe evaluation")
	}
}

// Cell: probes circuit open → no trip, judge still runs.
func TestProbes_LLM_CircuitOpen_FallsThroughToJudge(t *testing.T) {
	m := newLLMManager(t, allowJudge(), "deny")

	// Trip the breaker by failing 3 calls directly on the client.
	errServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer errServer.Close()
	client := probes.NewClient(errServer.URL, "test-model", "", 1*time.Second, 32,
		llm.WithCircuitBreaker(3, 1*time.Hour),
	)
	for i := 0; i < 3; i++ {
		client.Complete(context.Background(), "sys", "user") //nolint:errcheck
	}
	if !client.IsOpen() {
		t.Fatal("precondition: breaker should be open")
	}
	runner := probes.NewRunner(client, probes.StaticSpecs([]probes.Spec{{Name: "x", Threshold: 0.5, Aggregation: "max"}}), 0)
	m.SetProbeRunner(runner)

	req, _ := http.NewRequest("GET", "https://example.com", nil)
	decision, _, err := m.CheckApproval(policyCtx("policy"), req, "req11", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.Decision != types.DecisionAllow || decision.ApprovedBy != "llm" {
		t.Errorf("expected judge ALLOW when breaker open, got %+v", decision)
	}
	if !decision.ProbeCircuitOpen {
		t.Error("expected ProbeCircuitOpen=true in audit")
	}
}

// stubResolver is a minimal PolicyResolver that returns a fixed policy or an
// error keyed by ID. Tests use it without bringing in the llmpolicy package.
type stubResolver struct {
	policies map[string]*types.LLMPolicy
	err      error
}

func (r *stubResolver) Get(id string) (*types.LLMPolicy, error) {
	if r.err != nil {
		return nil, r.err
	}
	p, ok := r.policies[id]
	if !ok {
		return nil, errors.New("not found")
	}
	return p, nil
}

// capturingJudge records the system prompt seen on each call so tests can
// assert which policy actually drove the judge.
func capturingJudge(decision string, captured *[]string) *judge.LLMJudge {
	return judge.NewLLMJudge(&llm.TestAdapter{Fn: func(req llm.Request) (llm.Response, error) {
		*captured = append(*captured, req.System)
		return llm.Response{Text: `{"decision":"` + decision + `","reason":"ok"}`}, nil
	}})
}

// Cell: per-probe escalation. A gray-zone probe with JudgePolicyID set
// causes the manager to swap the user's policy for the resolved one when
// invoking the judge. Audit fields surface the override.
func TestProbes_LLM_GrayZone_EscalatesToPerProbeJudgePolicy(t *testing.T) {
	var prompts []string
	m := newLLMManager(t, capturingJudge("DENY", &prompts), "deny")

	override := &types.LLMPolicy{ID: "llmpol_jb", Prompt: "specialised jailbreak rules"}
	m.SetPolicyResolver(&stubResolver{policies: map[string]*types.LLMPolicy{
		"llmpol_jb": override,
	}})

	runner, server := newProbeRunnerServer(t,
		[]probes.Spec{
			{Name: "jailbreak", Threshold: 0.8, ClearThreshold: 0.1, Aggregation: "max", JudgePolicyID: "llmpol_jb"},
		},
		map[string][]float64{"jailbreak": {0.4}}, // gray zone
	)
	defer server.Close()
	m.SetProbeRunner(runner)

	req, _ := http.NewRequest("POST", "https://example.com/api", bytes.NewReader([]byte(`{"q":"x"}`)))
	decision, _, err := m.CheckApproval(policyCtxWithID("llmpol_user", "user policy"), req, "req-esc", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.Decision != types.DecisionDeny || decision.ApprovedBy != "llm" {
		t.Errorf("expected judge DENY, got %+v", decision)
	}
	if decision.LLMPolicyID != "llmpol_jb" {
		t.Errorf("LLMPolicyID = %q, want llmpol_jb (the override)", decision.LLMPolicyID)
	}
	if len(prompts) != 1 {
		t.Fatalf("expected one judge call, got %d", len(prompts))
	}
	if !strings.Contains(prompts[0], "specialised jailbreak rules") {
		t.Errorf("judge system prompt should embed override policy, got %q", prompts[0])
	}
	if strings.Contains(prompts[0], "user policy") {
		t.Errorf("judge system prompt should NOT include user policy when override active, got %q", prompts[0])
	}
}

// Cell: per-probe escalation falls back to the user's policy when the
// resolver returns an error.
func TestProbes_LLM_GrayZone_EscalationLookupFails_UsesUserPolicy(t *testing.T) {
	var prompts []string
	m := newLLMManager(t, capturingJudge("ALLOW", &prompts), "deny")
	m.SetPolicyResolver(&stubResolver{err: errors.New("db down")})

	runner, server := newProbeRunnerServer(t,
		[]probes.Spec{
			{Name: "jailbreak", Threshold: 0.8, ClearThreshold: 0.1, Aggregation: "max", JudgePolicyID: "missing"},
		},
		map[string][]float64{"jailbreak": {0.4}},
	)
	defer server.Close()
	m.SetProbeRunner(runner)

	req, _ := http.NewRequest("GET", "https://example.com", nil)
	decision, _, err := m.CheckApproval(policyCtxWithID("llmpol_user", "user policy"), req, "req-esc-err", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.LLMPolicyID != "llmpol_user" {
		t.Errorf("LLMPolicyID = %q, want llmpol_user (fallback)", decision.LLMPolicyID)
	}
	if len(prompts) != 1 || !strings.Contains(prompts[0], "user policy") {
		t.Errorf("judge should be invoked with user policy on lookup failure, got %v", prompts)
	}
}

// Cell: judge error with probe pass → fallback path keeps probe fields.
func TestProbes_LLM_JudgeErrorWithProbePass_FallbackKeepsProbeFields(t *testing.T) {
	m := newLLMManager(t, errorJudge(errors.New("judge call failed")), "deny")
	runner, server := newProbeRunnerServer(t,
		[]probes.Spec{{Name: "x", Threshold: 0.8, Aggregation: "max"}},
		map[string][]float64{"x": {0.2}},
	)
	defer server.Close()
	m.SetProbeRunner(runner)

	req, _ := http.NewRequest("GET", "https://example.com", nil)
	decision, _, err := m.CheckApproval(policyCtx("policy"), req, "req12", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.Decision != types.DecisionDeny || decision.ApprovedBy != "llm-fallback" {
		t.Errorf("expected fallback DENY when judge errors, got %+v", decision)
	}
	if decision.ProbeScores["x"] != 0.2 {
		t.Errorf("probe fields should still be populated on judge error path, got %v", decision.ProbeScores)
	}
}
