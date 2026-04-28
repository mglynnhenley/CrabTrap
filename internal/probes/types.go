// Package probes calls probe-demo (an OpenAI-compatible inference server
// that returns per-token activation scores from trained policy heads) and
// turns those scores into ALLOW/DENY signal for the approval pipeline.
package probes

// Spec configures one probe: its name (must match what probe-demo returns in
// the scores map), the fire threshold and optional clear threshold (both in
// [0, 1], clear <= fire when set), and how per-token scores collapse to a
// single number ("max" | "mean"). ClearThreshold==0 disables the confident-
// benign signal for that probe (AllClear cannot be true unless every spec
// sets a positive ClearThreshold).
//
// JudgePolicyID, when non-empty, names a per-probe LLM policy used in place
// of the user's policy when this probe lands in its own gray zone (didn't
// trip, didn't clear). It lets operators escalate ambiguous probe scores to
// a specialised prompt rather than the user's general policy.
type Spec struct {
	Name           string
	Threshold      float64
	ClearThreshold float64
	Aggregation    string
	JudgePolicyID  string
}

// Result is the outcome of one Runner.Evaluate call. Scores holds the
// aggregated score per probe name (empty when the probe call failed or the
// circuit breaker was open). Tripped is the name of the first probe that
// exceeded its fire threshold, or "" when none tripped. AllClear is true
// iff every spec has a positive ClearThreshold AND every observed score is
// <= that probe's ClearThreshold — i.e. the caller can safely skip the LLM
// judge. Aggregation repeats the method used (for audit logging); callers
// should not mix methods within one Result. CircuitOpen is true when the
// probe circuit breaker rejected the call without hitting probe-demo.
//
// GrayZoneProbe and GrayZonePolicyID are set when no probe tripped, the
// result wasn't AllClear, and at least one configured probe is in its own
// gray zone (above any clear_threshold, below threshold) AND has a non-
// empty JudgePolicyID. The first such probe (by spec order, which is
// priority) wins. Callers can use GrayZonePolicyID to escalate to a
// per-probe judge prompt instead of the caller's default policy.
type Result struct {
	Scores           map[string]float64
	Tripped          string
	AllClear         bool
	Aggregation      string
	CircuitOpen      bool
	GrayZoneProbe    string
	GrayZonePolicyID string
}
