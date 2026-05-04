package approval

import (
	"context"
	"net/http"
	"testing"

	"github.com/brexhq/CrabTrap/internal/probes"
	"github.com/brexhq/CrabTrap/pkg/types"
)

// stubProbeEvaluator returns a fixed Result for every Evaluate call and
// records the specs it was given.
type stubProbeEvaluator struct {
	result probes.Result
	calls  int
	specs  []probes.Spec
}

func (s *stubProbeEvaluator) Evaluate(ctx context.Context, specs []probes.Spec, method, url string, body []byte) probes.Result {
	s.calls++
	s.specs = specs
	return s.result
}

// policyWithProbes returns a context carrying a policy that has both a prompt
// and one or more probe attachments.
func policyWithProbes(prompt string, probesList ...types.PolicyProbe) context.Context {
	pol := &types.LLMPolicy{
		ID:     "llmpol_test",
		Prompt: prompt,
		Probes: probesList,
	}
	return context.WithValue(context.Background(), ContextKeyLLMPolicy, pol)
}

func TestProbeTrip_ShortCircuitsJudge(t *testing.T) {
	judgeCalls := 0
	manager := newLLMManager(t, countingJudge("ALLOW", &judgeCalls), "deny")
	stub := &stubProbeEvaluator{result: probes.Result{
		Tripped: &probes.Trip{Name: "injection", Score: 0.95, Threshold: 0.8},
		Scores:  map[string]float64{"injection": 0.95},
	}}
	manager.SetProbeRunner(stub)

	ctx := policyWithProbes("test policy",
		types.PolicyProbe{Name: "injection", Threshold: 0.8, ClearThreshold: 0.3})
	req, _ := http.NewRequest(http.MethodPost, "https://api.example.com/x", nil)

	decision, _, err := manager.CheckApproval(ctx, req, "req_probe_trip", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.Decision != types.DecisionDeny {
		t.Errorf("expected DENY, got %v", decision.Decision)
	}
	if decision.Channel != "probe" || decision.ApprovedBy != "probe" {
		t.Errorf("expected channel=probe approvedBy=probe, got %q/%q", decision.Channel, decision.ApprovedBy)
	}
	if decision.LLMPolicyID != "llmpol_test" {
		t.Errorf("expected LLMPolicyID=llmpol_test, got %q", decision.LLMPolicyID)
	}
	if decision.ProbeResponse == nil || decision.ProbeResponse.Result != "tripped" || decision.ProbeResponse.Tripped != "injection" {
		t.Errorf("ProbeResponse missing or wrong: %+v", decision.ProbeResponse)
	}
	if judgeCalls != 0 {
		t.Errorf("expected judge never called, got %d", judgeCalls)
	}
	if len(decision.ProbeResponse.Scores) != 1 {
		t.Fatalf("expected 1 score, got %d", len(decision.ProbeResponse.Scores))
	}
	s := decision.ProbeResponse.Scores[0]
	if s.Threshold != 0.8 || s.ClearThreshold != 0.3 {
		t.Errorf("ProbeScore must carry per-probe thresholds at decision time, got %+v", s)
	}
}

func TestProbeAllClear_ShortCircuitsJudge(t *testing.T) {
	judgeCalls := 0
	manager := newLLMManager(t, countingJudge("ALLOW", &judgeCalls), "deny")
	stub := &stubProbeEvaluator{result: probes.Result{
		AllClear: true,
		Scores:   map[string]float64{"injection": 0.05},
	}}
	manager.SetProbeRunner(stub)

	ctx := policyWithProbes("test policy",
		types.PolicyProbe{Name: "injection", Threshold: 0.8, ClearThreshold: 0.3})
	req, _ := http.NewRequest(http.MethodGet, "https://api.example.com/x", nil)

	decision, _, err := manager.CheckApproval(ctx, req, "req_probe_clear", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.Decision != types.DecisionAllow {
		t.Errorf("expected ALLOW, got %v", decision.Decision)
	}
	if decision.Channel != "probe" {
		t.Errorf("expected channel=probe, got %q", decision.Channel)
	}
	if decision.ProbeResponse == nil || decision.ProbeResponse.Result != "all_clear" {
		t.Errorf("ProbeResponse: %+v", decision.ProbeResponse)
	}
	if judgeCalls != 0 {
		t.Errorf("expected judge never called, got %d", judgeCalls)
	}
}

func TestProbeGrayZone_DefersToJudge(t *testing.T) {
	judgeCalls := 0
	manager := newLLMManager(t, countingJudge("ALLOW", &judgeCalls), "deny")
	stub := &stubProbeEvaluator{result: probes.Result{
		// Neither Tripped nor AllClear: gray zone.
		Scores: map[string]float64{"injection": 0.50},
	}}
	manager.SetProbeRunner(stub)

	ctx := policyWithProbes("test policy",
		types.PolicyProbe{Name: "injection", Threshold: 0.8, ClearThreshold: 0.3})
	req, _ := http.NewRequest(http.MethodGet, "https://api.example.com/x", nil)

	decision, _, err := manager.CheckApproval(ctx, req, "req_probe_gray", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.Decision != types.DecisionAllow {
		t.Errorf("expected judge ALLOW, got %v", decision.Decision)
	}
	if decision.Channel != "llm" {
		t.Errorf("expected channel=llm (judge), got %q", decision.Channel)
	}
	if judgeCalls != 1 {
		t.Errorf("expected exactly 1 judge call, got %d", judgeCalls)
	}
	if decision.ProbeResponse == nil || decision.ProbeResponse.Result != "gray_zone" {
		t.Errorf("expected ProbeResponse.Result=gray_zone on judge-decided row, got %+v", decision.ProbeResponse)
	}
	if len(decision.ProbeResponse.Scores) != 1 || decision.ProbeResponse.Scores[0].Score != 0.50 {
		t.Errorf("expected informational score 0.50, got %+v", decision.ProbeResponse.Scores)
	}
}

func TestPolicyWithoutProbes_SkipsProbeTier(t *testing.T) {
	judgeCalls := 0
	manager := newLLMManager(t, countingJudge("ALLOW", &judgeCalls), "deny")
	stub := &stubProbeEvaluator{result: probes.Result{
		Tripped: &probes.Trip{Name: "injection", Score: 0.95},
	}}
	manager.SetProbeRunner(stub)

	// Policy has no probes attached, so the probe tier must be skipped entirely
	// even though the runner is configured.
	ctx := policyWithProbes("test policy" /* no probes */)
	req, _ := http.NewRequest(http.MethodGet, "https://api.example.com/x", nil)

	decision, _, err := manager.CheckApproval(ctx, req, "req_no_probes", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.Decision != types.DecisionAllow {
		t.Errorf("expected ALLOW from judge, got %v", decision.Decision)
	}
	if stub.calls != 0 {
		t.Errorf("expected probe runner never called for empty Probes list, got %d calls", stub.calls)
	}
	if judgeCalls != 1 {
		t.Errorf("expected judge called once, got %d", judgeCalls)
	}
}

func TestProbeSkipped_FallsThroughWithReason(t *testing.T) {
	judgeCalls := 0
	manager := newLLMManager(t, countingJudge("ALLOW", &judgeCalls), "deny")
	stub := &stubProbeEvaluator{result: probes.Result{
		SkippedReason: "circuit_open",
		Scores:        map[string]float64{},
	}}
	manager.SetProbeRunner(stub)

	ctx := policyWithProbes("test policy",
		types.PolicyProbe{Name: "injection", Threshold: 0.8, ClearThreshold: 0.3})
	req, _ := http.NewRequest(http.MethodGet, "https://api.example.com/x", nil)

	decision, _, err := manager.CheckApproval(ctx, req, "req_probe_skip", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.Decision != types.DecisionAllow {
		t.Errorf("expected judge ALLOW (probe skipped), got %v", decision.Decision)
	}
	if judgeCalls != 1 {
		t.Errorf("expected judge called once, got %d", judgeCalls)
	}
	if decision.ProbeResponse == nil || decision.ProbeResponse.Result != "skipped" || decision.ProbeResponse.SkipReason != "circuit_open" {
		t.Errorf("expected ProbeResponse with Result=skipped, SkipReason=circuit_open, got %+v", decision.ProbeResponse)
	}
}
