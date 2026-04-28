package probes

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/brexhq/CrabTrap/internal/llm"
)

// DefaultTimeout is the per-request timeout for probe-demo calls.
const DefaultTimeout = 10 * time.Second

// DefaultMaxTokens is the OpenAI max_tokens we request. Probes only need a
// few continuation tokens to activate; generation cost is mostly overhead.
const DefaultMaxTokens = 32

// Protocol identifies the upstream probe service's wire dialect. The two
// supported backends share the OpenAI /v1/chat/completions URL but differ in
// what they expect in the request and what they return.
const (
	// ProtocolProbeDemo is the local probe-demo server (Qwen + trained
	// activation probes). Request: standard system+user chat. Response:
	// top-level `scores` map of per-token floats keyed by probe name.
	ProtocolProbeDemo = "probe_demo"
	// ProtocolModal is the Modal-hosted probe API. Mode is selected by the
	// last message role: assistant forces score-only (Mode A), user triggers
	// an upstream completion (Mode B, unwanted here). Response: top-level
	// `probe` verdict object plus choices[].finish_reason="content_filter"
	// when flagged. Scores derived from the verdict so the runner stays
	// protocol-agnostic.
	ProtocolModal = "modal"
)

// ClientResponse holds the parsed probe-demo completion, including per-token
// activation scores keyed by probe name.
type ClientResponse struct {
	Scores       map[string][]float64
	DurationMs   int
	InputTokens  int
	OutputTokens int
}

// Client posts chat completions to a probe-demo server (OpenAI-compatible)
// with the `include_scores: true` extension.
type Client struct {
	httpClient      *http.Client
	endpoint        string // probe-demo base URL, e.g. http://localhost:8000
	model           string
	apiKey          string
	timeout         time.Duration
	maxTokens       int
	protocol        string
	modalProbeNames []string // Modal-only: configured probe names to key the verdict under

	*llm.Resilience
}

// NewClient constructs a probe-demo client pointing at endpoint (no trailing
// slash required). A zero timeout falls back to DefaultTimeout; a zero
// maxTokens falls back to DefaultMaxTokens. apiKey is optional — when non-empty
// it is sent as `Authorization: Bearer <apiKey>`; the local probe-demo server
// ignores auth entirely, so leave it blank there.
func NewClient(endpoint, model, apiKey string, timeout time.Duration, maxTokens int, opts ...llm.ResilienceOption) *Client {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	if maxTokens <= 0 {
		maxTokens = DefaultMaxTokens
	}
	return &Client{
		httpClient: &http.Client{},
		endpoint:   endpoint,
		model:      model,
		apiKey:     apiKey,
		timeout:    timeout,
		maxTokens:  maxTokens,
		protocol:   ProtocolProbeDemo,
		Resilience: llm.NewResilience(opts...),
	}
}

// WithProtocol selects the wire dialect spoken by the upstream probe service.
// Empty or unknown values fall back to ProtocolProbeDemo so misconfigured
// deployments behave the same as the historical default. Returns the receiver
// for fluent construction in main.go.
func (c *Client) WithProtocol(protocol string) *Client {
	switch protocol {
	case ProtocolModal:
		c.protocol = ProtocolModal
	default:
		c.protocol = ProtocolProbeDemo
	}
	return c
}

// WithModalProbeNames binds the configured probe names that the Modal verdict
// will be emitted under. Modal returns a single anonymous verdict (the probe
// is selected at deploy time on the Modal app side), so the gateway-side
// names must be supplied here for the runner's spec lookup to succeed. Has
// no effect outside Modal protocol.
func (c *Client) WithModalProbeNames(names []string) *Client {
	c.modalProbeNames = append([]string(nil), names...)
	return c
}

// setAuth adds the Authorization header when an API key is configured. Probe
// calls and health/model discovery all go through this.
func (c *Client) setAuth(req *http.Request) {
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}
}

// chatMessage mirrors probe-demo's ChatMessage schema.
type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// chatRequest mirrors probe-demo's ChatCompletionRequest. probe_path is
// omitted so probe-demo returns scores for every probe loaded server-side
// via PROBE_PATH.
type chatRequest struct {
	Model         string        `json:"model"`
	Messages      []chatMessage `json:"messages"`
	Stream        bool          `json:"stream"`
	MaxTokens     int           `json:"max_tokens"`
	IncludeScores bool          `json:"include_scores"`
}

// chatUsage mirrors probe-demo's CompletionUsage.
type chatUsage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

// chatChoice captures the OpenAI choice fields we use. Modal sets
// FinishReason to "content_filter" when its probe trips, providing a
// finish_reason-only signal even when the verdict object is sparse.
type chatChoice struct {
	FinishReason string `json:"finish_reason"`
}

// chatResponse covers both probe-demo and Modal responses. probe-demo populates
// only Usage and Scores; Modal populates Choices (with finish_reason) and Probe
// (verdict payload). Modal Mode-A returns zeroed Usage since no upstream
// completion was generated. Each backend ignores the other's fields, so this
// single shape decodes cleanly from either response.
type chatResponse struct {
	Usage   chatUsage            `json:"usage"`
	Scores  map[string][]float64 `json:"scores"`
	Choices []chatChoice         `json:"choices"`
	Probe   json.RawMessage      `json:"probe"` // Modal verdict payload; see modalProbeVerdict
}

// modalProbeVerdict captures the live shape of the Modal probe API's verdict:
// per-token probabilities (the same per-token signal probe-demo emits), a
// server-side threshold, and a flagged flag. CompletionProb is the aggregate
// the server uses internally; we prefer TokenProbs when present so the
// runner's own aggregation honors the operator-configured method.
type modalProbeVerdict struct {
	CompletionProb float64   `json:"completion_prob"`
	Threshold      float64   `json:"threshold"`
	Flagged        bool      `json:"flagged"`
	NTokens        int       `json:"n_tokens"`
	TokenProbs     []float64 `json:"token_probs"`
}

// Complete posts (system, user) to /v1/chat/completions and returns the
// per-probe per-token scores. Circuit-breaker state is respected via the
// embedded Resilience; when the breaker is open, Complete returns an error
// without hitting the network and callers should inspect IsOpen().
func (c *Client) Complete(ctx context.Context, system, user string) (ClientResponse, error) {
	if err := c.Acquire(ctx, "probes"); err != nil {
		return ClientResponse{}, err
	}
	defer c.Release()

	callCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	body, err := json.Marshal(chatRequest{
		Model:         c.model,
		Messages:      c.buildMessages(system, user),
		Stream:        false,
		MaxTokens:     c.maxTokens,
		IncludeScores: true,
	})
	if err != nil {
		return ClientResponse{}, fmt.Errorf("failed to marshal probe request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(callCtx, http.MethodPost, c.endpoint+"/v1/chat/completions", bytes.NewReader(body))
	if err != nil {
		return ClientResponse{}, fmt.Errorf("failed to create probe request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	c.setAuth(httpReq)

	start := time.Now()
	httpResp, err := c.httpClient.Do(httpReq)
	durationMs := int(time.Since(start).Milliseconds())
	if err != nil {
		c.RecordFailure()
		return ClientResponse{DurationMs: durationMs}, fmt.Errorf("probe request failed: %w", err)
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != http.StatusOK {
		c.RecordFailure()
		errBody, _ := io.ReadAll(httpResp.Body)
		return ClientResponse{DurationMs: durationMs}, fmt.Errorf("probe API error (status %d): %s", httpResp.StatusCode, string(errBody))
	}

	var parsed chatResponse
	if err := json.NewDecoder(httpResp.Body).Decode(&parsed); err != nil {
		c.RecordFailure()
		return ClientResponse{DurationMs: durationMs}, fmt.Errorf("failed to decode probe response: %w", err)
	}

	c.RecordSuccess()
	scores := parsed.Scores
	if c.protocol == ProtocolModal && len(scores) == 0 {
		scores = c.scoresFromModalVerdict(parsed.Probe, parsed.Choices)
	}
	return ClientResponse{
		Scores:       scores,
		DurationMs:   durationMs,
		InputTokens:  parsed.Usage.PromptTokens,
		OutputTokens: parsed.Usage.CompletionTokens,
	}, nil
}

// buildMessages constructs the chat payload for the configured protocol.
// probe-demo expects a normal system+user pair. Modal selects scoring mode by
// the last message's role: assistant => score-only (Mode A), which is what we
// always want here since the gateway is intercepting an outgoing request, not
// asking Modal to generate a fresh completion.
func (c *Client) buildMessages(system, user string) []chatMessage {
	if c.protocol == ProtocolModal {
		return []chatMessage{{Role: "assistant", Content: user}}
	}
	return []chatMessage{
		{Role: "system", Content: system},
		{Role: "user", Content: user},
	}
}

// scoresFromModalVerdict translates Modal's anonymous probe verdict into the
// per-probe score map the runner expects. Modal's response carries a single
// verdict (the probe is fixed at deploy time on the Modal side) with a real
// per-token score array, so we pass that array straight through under each
// configured probe name — the runner will then aggregate (max/mean) and
// threshold-check exactly as it does for probe-demo. When token_probs is
// missing we fall back to the flagged flag (or the choices[].finish_reason
// content_filter signal) and emit a synthetic 1.0/0.0 instead so the
// threshold gate still works.
func (c *Client) scoresFromModalVerdict(probeRaw json.RawMessage, choices []chatChoice) map[string][]float64 {
	contentFiltered := false
	for _, ch := range choices {
		if ch.FinishReason == "content_filter" {
			contentFiltered = true
			break
		}
	}

	var verdict modalProbeVerdict
	if len(probeRaw) > 0 {
		_ = json.Unmarshal(probeRaw, &verdict)
	}

	tokenScores := verdict.TokenProbs
	if len(tokenScores) == 0 {
		flag := 0.0
		if verdict.Flagged || contentFiltered {
			flag = 1.0
		}
		tokenScores = []float64{flag}
	}

	names := c.modalProbeNames
	if len(names) == 0 {
		// No operator-supplied names: emit nothing. The runner will see an
		// empty Scores map and fall through to the judge instead of silently
		// missing the verdict — clearer failure mode than a wrong-keyed map.
		return map[string][]float64{}
	}

	scores := make(map[string][]float64, len(names))
	for _, name := range names {
		scores[name] = tokenScores
	}
	return scores
}

// Ping issues a GET /health against probe-demo. It exists so operators get
// fast, clear feedback when endpoint/auth is misconfigured instead of the
// first live request failing opaquely. It neither trips nor records to the
// circuit breaker — a transient startup blip should not pre-open the breaker.
func (c *Client) Ping(ctx context.Context) error {
	callCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(callCtx, http.MethodGet, c.endpoint+"/health", nil)
	if err != nil {
		return fmt.Errorf("failed to create health request: %w", err)
	}
	c.setAuth(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("health request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("health endpoint returned status %d: %s", resp.StatusCode, string(body))
	}
	return nil
}

// Discover returns the probe names exposed by the upstream probe-demo
// server. probe-demo doesn't have a dedicated discovery endpoint, so we
// trigger a minimal scoring call (the constant prompts mirror Runner so
// any probe-demo configuration that works in production also works here)
// and read the keys back from the scores map. Used by the admin UI to
// populate the probe-onboarding picker.
func (c *Client) Discover(ctx context.Context) ([]string, error) {
	resp, err := c.Complete(ctx, "You are a helpful assistant.", "ping")
	if err != nil {
		return nil, fmt.Errorf("probe discovery failed: %w", err)
	}
	names := make([]string, 0, len(resp.Scores))
	for name := range resp.Scores {
		names = append(names, name)
	}
	return names, nil
}

// modelsResponse mirrors the OpenAI /v1/models shape.
type modelsResponse struct {
	Data []struct {
		ID string `json:"id"`
	} `json:"data"`
}

// ListModels returns the IDs advertised by probe-demo at /v1/models. Used
// only for startup logging/discovery. Like Ping, it does not interact with
// the circuit breaker.
func (c *Client) ListModels(ctx context.Context) ([]string, error) {
	callCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(callCtx, http.MethodGet, c.endpoint+"/v1/models", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create models request: %w", err)
	}
	c.setAuth(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("models request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("models endpoint returned status %d: %s", resp.StatusCode, string(body))
	}

	var parsed modelsResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, fmt.Errorf("failed to decode models response: %w", err)
	}
	ids := make([]string, len(parsed.Data))
	for i, m := range parsed.Data {
		ids[i] = m.ID
	}
	return ids, nil
}
