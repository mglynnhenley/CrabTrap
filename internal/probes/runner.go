package probes

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// DefaultMaxBodyBytes is the probe-specific body cap — half the judge's cap
// (16384) to bound probe-demo forward-pass cost. Operators can override via
// config.
const DefaultMaxBodyBytes = 8192

// Aggregation methods for collapsing per-token scores to a single number.
const (
	AggregationMax  = "max"
	AggregationMean = "mean"
)

// probeSystemPrompt is deliberately neutral. Policy-head probes are trained on
// natural conversational generations, so we want the target model to respond
// to the user content as it normally would; probe scores come from activations
// during that generation. An analytical framing would bias the model away from
// the behaviours the probes were trained to detect.
const probeSystemPrompt = `You are a helpful assistant.`

// SpecsProvider returns the set of probe specs to evaluate for the given
// LLM policy. It is invoked once per Evaluate so the admin UI can mutate
// per-policy attachments without a gateway restart. An empty policyID asks
// for the global fallback (the rows in the original `probes` table) — the
// runtime path callers without a resolved user policy use.
//
// Returning an error fails the evaluation; a zero-length slice is treated as
// "no probes configured" and short-circuits to a non-tripping, non-clear
// Result so the caller falls through to the judge.
type SpecsProvider func(ctx context.Context, policyID string) ([]Spec, error)

// StaticSpecs adapts a fixed slice into a SpecsProvider — useful for tests
// and for callers that don't need hot reload. The policyID is ignored.
func StaticSpecs(specs []Spec) SpecsProvider {
	return func(context.Context, string) ([]Spec, error) { return specs, nil }
}

// Runner orchestrates a probe-demo call and reduces the returned per-token
// scores into a pass/trip decision.
type Runner struct {
	client       *Client
	specs        SpecsProvider
	maxBodyBytes int
}

// NewRunner wraps a Client with a probe specs provider and body cap. A
// non-positive maxBodyBytes falls back to DefaultMaxBodyBytes. Callers that
// already have a fixed slice can pass StaticSpecs(specs).
func NewRunner(client *Client, specs SpecsProvider, maxBodyBytes int) *Runner {
	if maxBodyBytes <= 0 {
		maxBodyBytes = DefaultMaxBodyBytes
	}
	return &Runner{
		client:       client,
		specs:        specs,
		maxBodyBytes: maxBodyBytes,
	}
}

// Evaluate serializes the HTTP request, calls probe-demo, aggregates per-token
// scores per Spec, and reports the first probe whose aggregated score meets
// or exceeds its threshold.
//
// policyID names the LLM policy attached to the request so the runner can
// resolve the policy-scoped probe set. Pass "" to request the global
// fallback (Phase 1/2 behaviour).
//
// When the circuit breaker is open, Evaluate returns a Result with
// CircuitOpen=true and nil error so the caller can log the degraded state
// and fall through to the judge path. Other errors (HTTP failure, bad JSON)
// return a zero Result plus the error.
func (r *Runner) Evaluate(ctx context.Context, method, rawURL string, headers http.Header, body, policyID string) (Result, error) {
	if r.client.IsOpen() {
		return Result{CircuitOpen: true}, nil
	}

	specs, err := r.specs(ctx, policyID)
	if err != nil {
		return Result{}, fmt.Errorf("probe specs provider failed: %w", err)
	}
	if len(specs) == 0 {
		// No probes configured: nothing to score, nothing to clear. The
		// approval manager will fall through to the judge.
		return Result{Scores: map[string]float64{}}, nil
	}

	userMsg := extractProbeInput(body, r.maxBodyBytes)
	resp, err := r.client.Complete(ctx, probeSystemPrompt, userMsg)
	if err != nil {
		return Result{}, fmt.Errorf("probe client complete failed: %w", err)
	}

	aggregated := make(map[string]float64, len(specs))
	var tripped, trippedAggregation string
	var grayZoneProbe, grayZonePolicyID string
	// allClear starts true and is forced false by any spec that either lacks
	// a positive ClearThreshold (operator hasn't opted in) or whose aggregated
	// score exceeds its clear line.
	allClear := true
	for _, spec := range specs {
		agg := spec.Aggregation
		if agg == "" {
			agg = AggregationMax
		}
		score := aggregate(resp.Scores[spec.Name], agg)
		aggregated[spec.Name] = score
		if tripped == "" && score >= spec.Threshold {
			tripped = spec.Name
			trippedAggregation = agg
		}
		if spec.ClearThreshold <= 0 || score > spec.ClearThreshold {
			allClear = false
		}
		// First spec (in priority order) that is in its own gray zone AND has
		// a per-probe judge policy wins the escalation. "Gray zone" here means
		// the probe is uncertain: didn't trip and either has no clear opt-in
		// or its score sits above the clear line. A confidently-clear spec
		// shouldn't drag a different probe's gray-zone judge into the call.
		if grayZonePolicyID == "" && spec.JudgePolicyID != "" && score < spec.Threshold {
			if spec.ClearThreshold <= 0 || score > spec.ClearThreshold {
				grayZoneProbe = spec.Name
				grayZonePolicyID = spec.JudgePolicyID
			}
		}
	}

	// A tripped probe always overrides AllClear — ClearThreshold is bounded
	// above by Threshold at config time, so this is belt-and-braces against
	// operator typos or future relaxation of that rule.
	if tripped != "" {
		allClear = false
	}

	return Result{
		Scores:           aggregated,
		Tripped:          tripped,
		AllClear:         allClear,
		Aggregation:      trippedAggregation,
		GrayZoneProbe:    grayZoneProbe,
		GrayZonePolicyID: grayZonePolicyID,
	}, nil
}

// extractProbeInput returns the text we hand to probe-demo for activation
// scoring. Policy-head probes were trained on activations during a single
// user→assistant generation, so we feed only the tail of the conversation
// starting at the most recent user message: that turn's user content plus any
// assistant tool_calls and tool results that followed it. This keeps the
// probe in-distribution (full prior dialogue would shift Qwen's behaviour
// and dilute signal) while still exposing what tool the model just decided
// to call and what the tool returned — the freshest signals for an agentic
// loop. System messages are skipped so the caller's persona (e.g. aider's
// "you are a bank CS bot") can't drag Qwen off the trained distribution.
//
// Falls back to the raw (capped) body for non-chat traffic.
func extractProbeInput(body string, maxBytes int) string {
	if maxBytes <= 0 {
		maxBytes = DefaultMaxBodyBytes
	}

	type messageStruct struct {
		Role      string          `json:"role"`
		Content   json.RawMessage `json:"content"`
		ToolCalls []struct {
			Function struct {
				Name      string `json:"name"`
				Arguments string `json:"arguments"`
			} `json:"function"`
		} `json:"tool_calls,omitempty"`
	}

	var req struct {
		Messages []messageStruct `json:"messages"`
	}
	if err := json.Unmarshal([]byte(body), &req); err == nil && len(req.Messages) > 0 {
		// When the request involves any tool call or tool result, include the
		// full conversation so the probe can evaluate the tool action in
		// context of the originating user intent — a short follow-up like
		// "go ahead" is innocuous alone but may be malicious given the prior
		// turns. For pure user/assistant chat we keep the tighter tail to
		// stay in distribution.
		hasToolActivity := false
		for _, m := range req.Messages {
			if strings.EqualFold(m.Role, "tool") || len(m.ToolCalls) > 0 {
				hasToolActivity = true
				break
			}
		}

		tail := req.Messages
		if !hasToolActivity {
			lastUser := -1
			for i, m := range req.Messages {
				if strings.EqualFold(m.Role, "user") {
					lastUser = i
				}
			}
			if lastUser >= 0 {
				tail = req.Messages[lastUser:]
			}
		}

		var parts []string
		for _, m := range tail {
			if strings.EqualFold(m.Role, "system") {
				continue
			}
			parts = appendMessageContent(parts, m.Content)
			for _, tc := range m.ToolCalls {
				if tc.Function.Name == "" && tc.Function.Arguments == "" {
					continue
				}
				parts = append(parts, fmt.Sprintf(
					"[tool_call name=%s arguments=%s]",
					tc.Function.Name, tc.Function.Arguments))
			}
		}
		if len(parts) > 0 {
			text := strings.Join(parts, "\n")
			if len(text) > maxBytes {
				text = text[:maxBytes]
			}
			return text
		}
	}

	if len(body) > maxBytes {
		return body[:maxBytes]
	}
	return body
}

// appendMessageContent handles both the string shape (OpenAI classic) and the
// array-of-parts shape (Anthropic / multimodal OpenAI), pulling out text.
func appendMessageContent(parts []string, raw json.RawMessage) []string {
	if len(raw) == 0 {
		return parts
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		if s != "" {
			parts = append(parts, s)
		}
		return parts
	}
	var arr []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	if err := json.Unmarshal(raw, &arr); err == nil {
		for _, p := range arr {
			if p.Text != "" {
				parts = append(parts, p.Text)
			}
		}
	}
	return parts
}

// aggregate collapses a per-token score slice to a single value. Empty input
// (e.g. probe-demo returned completion_tokens: 0, or the probe name is not
// in the response) returns 0.0, which can never trip a non-zero threshold.
func aggregate(tokens []float64, method string) float64 {
	if len(tokens) == 0 {
		return 0.0
	}
	switch method {
	case AggregationMean:
		var sum float64
		for _, v := range tokens {
			sum += v
		}
		return sum / float64(len(tokens))
	default: // "max" is the default and fallback.
		m := tokens[0]
		for _, v := range tokens[1:] {
			if v > m {
				m = v
			}
		}
		return m
	}
}
