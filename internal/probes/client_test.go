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

func probeSuccessResponse(scores map[string][]float64) []byte {
	resp := map[string]interface{}{
		"id":      "chatcmpl-test",
		"object":  "chat.completion",
		"created": 1700000000,
		"model":   "test-model",
		"choices": []map[string]interface{}{{
			"index": 0,
			"message": map[string]interface{}{
				"role":    "assistant",
				"content": "The request fetches a public homepage.",
			},
			"finish_reason": "stop",
		}},
		"usage": map[string]int{
			"prompt_tokens":     42,
			"completion_tokens": 7,
			"total_tokens":      49,
		},
		"scores": scores,
	}
	b, _ := json.Marshal(resp)
	return b
}

func newTestClient(t *testing.T, serverURL string) *Client {
	t.Helper()
	return NewClient(serverURL, "test-model", "", 5*time.Second, 32)
}

func TestClientComplete_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(probeSuccessResponse(map[string][]float64{
			"exfiltration": {0.1, 0.2, 0.15},
			"jailbreak":    {0.05, 0.08},
		}))
	}))
	defer server.Close()

	c := newTestClient(t, server.URL)
	resp, err := c.Complete(context.Background(), "sys", "user")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resp.Scores) != 2 {
		t.Errorf("expected 2 probe entries, got %d", len(resp.Scores))
	}
	if got := resp.Scores["exfiltration"]; len(got) != 3 {
		t.Errorf("expected 3 exfiltration scores, got %v", got)
	}
	if resp.InputTokens != 42 || resp.OutputTokens != 7 {
		t.Errorf("usage fields not set: %+v", resp)
	}
	if resp.DurationMs <= 0 {
		t.Errorf("DurationMs should be > 0, got %d", resp.DurationMs)
	}
}

func TestClientComplete_SendsIncludeScoresAndMessages(t *testing.T) {
	var capturedBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.Write(probeSuccessResponse(map[string][]float64{}))
	}))
	defer server.Close()

	c := newTestClient(t, server.URL)
	if _, err := c.Complete(context.Background(), "system-prompt", "user-msg"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var parsed struct {
		Model         string `json:"model"`
		Messages      []struct{ Role, Content string }
		Stream        bool `json:"stream"`
		MaxTokens     int  `json:"max_tokens"`
		IncludeScores bool `json:"include_scores"`
	}
	if err := json.Unmarshal(capturedBody, &parsed); err != nil {
		t.Fatalf("failed to parse captured body: %v\nbody=%s", err, capturedBody)
	}
	if !parsed.IncludeScores {
		t.Error("include_scores should be true")
	}
	if parsed.Stream {
		t.Error("stream should be false")
	}
	if parsed.MaxTokens != 32 {
		t.Errorf("max_tokens = %d, want 32", parsed.MaxTokens)
	}
	if parsed.Model != "test-model" {
		t.Errorf("model = %q, want test-model", parsed.Model)
	}
	if len(parsed.Messages) != 2 {
		t.Fatalf("expected 2 messages, got %d", len(parsed.Messages))
	}
	if parsed.Messages[0].Role != "system" || parsed.Messages[0].Content != "system-prompt" {
		t.Errorf("system message wrong: %+v", parsed.Messages[0])
	}
	if parsed.Messages[1].Role != "user" || parsed.Messages[1].Content != "user-msg" {
		t.Errorf("user message wrong: %+v", parsed.Messages[1])
	}
}

func TestClientComplete_HTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"boom"}`))
	}))
	defer server.Close()

	c := newTestClient(t, server.URL)
	_, err := c.Complete(context.Background(), "sys", "user")
	if err == nil {
		t.Fatal("expected error for 500 response")
	}
	if !strings.Contains(err.Error(), "status 500") {
		t.Errorf("error should mention status 500, got %v", err)
	}
}

func TestClientComplete_MalformedJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`not json`))
	}))
	defer server.Close()

	c := newTestClient(t, server.URL)
	_, err := c.Complete(context.Background(), "sys", "user")
	if err == nil {
		t.Fatal("expected error for malformed JSON")
	}
}

func TestClientComplete_EmptyScoresMap(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(probeSuccessResponse(nil))
	}))
	defer server.Close()

	c := newTestClient(t, server.URL)
	resp, err := c.Complete(context.Background(), "sys", "user")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Scores != nil && len(resp.Scores) != 0 {
		t.Errorf("expected empty/nil scores, got %v", resp.Scores)
	}
}

func TestClientComplete_SendsAuthorizationWhenAPIKeySet(t *testing.T) {
	var gotAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		w.Write(probeSuccessResponse(map[string][]float64{}))
	}))
	defer server.Close()

	c := NewClient(server.URL, "test-model", "sk-secret", 5*time.Second, 32)
	if _, err := c.Complete(context.Background(), "sys", "user"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotAuth != "Bearer sk-secret" {
		t.Errorf("Authorization header = %q, want %q", gotAuth, "Bearer sk-secret")
	}
}

func TestClientComplete_OmitsAuthorizationWhenNoAPIKey(t *testing.T) {
	var gotAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		w.Write(probeSuccessResponse(map[string][]float64{}))
	}))
	defer server.Close()

	c := newTestClient(t, server.URL)
	if _, err := c.Complete(context.Background(), "sys", "user"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotAuth != "" {
		t.Errorf("Authorization header should be empty, got %q", gotAuth)
	}
}

func TestClientPing_Success(t *testing.T) {
	var gotPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Write([]byte(`{"status":"ok"}`))
	}))
	defer server.Close()

	c := newTestClient(t, server.URL)
	if err := c.Ping(context.Background()); err != nil {
		t.Fatalf("Ping: unexpected error: %v", err)
	}
	if gotPath != "/health" {
		t.Errorf("Ping hit path = %q, want /health", gotPath)
	}
}

func TestClientPing_NonOKReturnsError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte(`{"status":"down"}`))
	}))
	defer server.Close()

	c := newTestClient(t, server.URL)
	err := c.Ping(context.Background())
	if err == nil {
		t.Fatal("expected error for 503 response")
	}
	if !strings.Contains(err.Error(), "status 503") {
		t.Errorf("error should mention status 503, got %v", err)
	}
}

func TestClientPing_DoesNotAffectCircuitBreaker(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	// Low threshold — if Ping recorded failures, this would trip.
	c := NewClient(server.URL, "test-model", "", 1*time.Second, 32, llm.WithCircuitBreaker(2, 1*time.Hour))
	for i := 0; i < 5; i++ {
		_ = c.Ping(context.Background())
	}
	if c.IsOpen() {
		t.Error("Ping failures should not open the circuit breaker")
	}
}

func TestClientListModels_ParsesIDs(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/models" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"object":"list","data":[{"id":"a"},{"id":"b"}]}`))
	}))
	defer server.Close()

	c := newTestClient(t, server.URL)
	ids, err := c.ListModels(context.Background())
	if err != nil {
		t.Fatalf("ListModels: unexpected error: %v", err)
	}
	if len(ids) != 2 || ids[0] != "a" || ids[1] != "b" {
		t.Errorf("ids = %v, want [a b]", ids)
	}
}

func TestClientListModels_HTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	c := newTestClient(t, server.URL)
	_, err := c.ListModels(context.Background())
	if err == nil {
		t.Fatal("expected error for 404 response")
	}
}

// modalSuccessResponse mirrors the live shape returned by the Modal probe API
// (https://mglynnhenley--probe-api.modal.run): finish_reason="content_filter"
// when flagged, plus a top-level `probe` object with per-token probabilities.
func modalSuccessResponse(flagged bool, tokenProbs []float64) []byte {
	finish := "stop"
	if flagged {
		finish = "content_filter"
	}
	resp := map[string]interface{}{
		"id":      "chatcmpl-probe-test",
		"object":  "chat.completion",
		"created": 1777368187,
		"model":   "default",
		"choices": []map[string]interface{}{{
			"index":         0,
			"message":       map[string]interface{}{"role": "assistant", "content": "anything"},
			"finish_reason": finish,
		}},
		"usage": map[string]int{"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
		"probe": map[string]interface{}{
			"completion_prob": 0.99,
			"threshold":       0.5,
			"flagged":         flagged,
			"n_tokens":        len(tokenProbs),
			"token_probs":     tokenProbs,
		},
	}
	b, _ := json.Marshal(resp)
	return b
}

func TestClientComplete_ModalSendsAssistantOnlyMessage(t *testing.T) {
	var capturedBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.Write(modalSuccessResponse(false, []float64{0.01, 0.02}))
	}))
	defer server.Close()

	c := newTestClient(t, server.URL).WithProtocol(ProtocolModal)
	if _, err := c.Complete(context.Background(), "system-prompt", "user-msg"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var parsed struct {
		Messages []struct{ Role, Content string }
	}
	if err := json.Unmarshal(capturedBody, &parsed); err != nil {
		t.Fatalf("failed to parse captured body: %v\nbody=%s", err, capturedBody)
	}
	if len(parsed.Messages) != 1 {
		t.Fatalf("Modal request must send exactly one message (last=assistant); got %d", len(parsed.Messages))
	}
	if parsed.Messages[0].Role != "assistant" {
		t.Errorf("Modal last message role = %q, want assistant (Mode A trigger)", parsed.Messages[0].Role)
	}
	if parsed.Messages[0].Content != "user-msg" {
		t.Errorf("Modal assistant content should mirror user input, got %q", parsed.Messages[0].Content)
	}
}

func TestClientComplete_ModalEmitsTokenProbsUnderConfiguredNames(t *testing.T) {
	tokenProbs := []float64{0.1, 0.95, 0.4}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(modalSuccessResponse(true, tokenProbs))
	}))
	defer server.Close()

	c := newTestClient(t, server.URL).
		WithProtocol(ProtocolModal).
		WithModalProbeNames([]string{"financial_advice", "tax_advice"})

	resp, err := c.Complete(context.Background(), "sys", "user-msg")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, name := range []string{"financial_advice", "tax_advice"} {
		got := resp.Scores[name]
		if len(got) != len(tokenProbs) {
			t.Errorf("%s: token slice len = %d, want %d", name, len(got), len(tokenProbs))
			continue
		}
		for i := range tokenProbs {
			if got[i] != tokenProbs[i] {
				t.Errorf("%s[%d] = %v, want %v", name, i, got[i], tokenProbs[i])
			}
		}
	}
}

func TestClientComplete_ModalFallsBackToFlaggedWhenNoTokenProbs(t *testing.T) {
	// Verdict missing token_probs but content_filter is set — runner should
	// still see a synthetic 1.0 score so threshold checks trip.
	resp := map[string]interface{}{
		"choices": []map[string]interface{}{{"finish_reason": "content_filter"}},
		"usage":   map[string]int{},
		"probe":   map[string]interface{}{"flagged": true},
	}
	b, _ := json.Marshal(resp)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(b)
	}))
	defer server.Close()

	c := newTestClient(t, server.URL).
		WithProtocol(ProtocolModal).
		WithModalProbeNames([]string{"financial_advice"})

	got, err := c.Complete(context.Background(), "sys", "user")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	scores := got.Scores["financial_advice"]
	if len(scores) != 1 || scores[0] != 1.0 {
		t.Errorf("flagged fallback scores = %v, want [1.0]", scores)
	}
}

func TestClientComplete_ProbeDemoUnchangedByModalFields(t *testing.T) {
	// Sanity: the default protocol still consumes the Scores map and ignores
	// any incidental probe field that might come back.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(probeSuccessResponse(map[string][]float64{"jailbreak": {0.9}}))
	}))
	defer server.Close()

	c := newTestClient(t, server.URL) // default = ProtocolProbeDemo
	resp, err := c.Complete(context.Background(), "sys", "user")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := resp.Scores["jailbreak"]; len(got) != 1 || got[0] != 0.9 {
		t.Errorf("probe-demo score lookup broken: %v", resp.Scores)
	}
}

func TestClientComplete_CircuitBreakerTrips(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	c := NewClient(server.URL, "test-model", "", 1*time.Second, 32,
		llm.WithCircuitBreaker(3, 1*time.Hour),
	)

	for i := 0; i < 3; i++ {
		if _, err := c.Complete(context.Background(), "sys", "user"); err == nil {
			t.Fatalf("call %d: expected error, got nil", i)
		}
	}
	if !c.IsOpen() {
		t.Fatal("expected circuit breaker to be open after 3 failures")
	}

	_, err := c.Complete(context.Background(), "sys", "user")
	if err == nil {
		t.Fatal("expected circuit-open error")
	}
	if !strings.Contains(err.Error(), "circuit breaker open") {
		t.Errorf("expected circuit breaker open error, got %v", err)
	}
}
