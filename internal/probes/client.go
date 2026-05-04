package probes

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// Client talks to the Modal hallucination-probe service.
//
// The service is single-purpose: each endpoint scores text along one
// dimension (today: hallucination probability per token) and streams the
// result back over SSE. There is no probe-name dispatch in the wire
// protocol — Spec.Name is therefore an audit-log label only, and every
// spec attached to a policy hits the same endpoint.
type Client struct {
	httpClient *http.Client
	endpoint   string
	apiKey     string
	batchSize  int
}

// NewClient constructs a probe-service client. endpoint is the full URL of
// the streaming analyze endpoint (no path is appended). apiKey is optional;
// if non-empty, sent as Bearer.
func NewClient(endpoint, apiKey string, batchSize int) *Client {
	if batchSize <= 0 {
		batchSize = 8
	}
	return &Client{
		httpClient: &http.Client{},
		endpoint:   strings.TrimRight(endpoint, "/"),
		apiKey:     apiKey,
		batchSize:  batchSize,
	}
}

// analyzeRequest matches the Modal endpoint's input schema.
type analyzeRequest struct {
	Text       string `json:"text"`
	BatchSize  int    `json:"batch_size"`
	UserPrompt string `json:"user_prompt,omitempty"`
}

// analyzeDoneEvent is the only SSE event we care about — terminal, with
// the full per-token probability vector. Earlier `analyze_batch` events
// are streamed for UIs but ignored here: the final `analyze_done` carries
// the full result.
type analyzeDoneEvent struct {
	Type       string    `json:"type"`
	ProbeProbs []float64 `json:"probe_probs"`
}

// Score sends one analyze request and returns the aggregate probe score for
// the given text. probeName is recorded only as an audit-log label; the wire
// payload does not include it.
//
// Aggregation: max(probe_probs) — a single high-probability token is enough
// to trip the probe. This matches the operator's intuition for hallucination
// detection (one fabricated claim is enough) and is the most defensive of
// the obvious aggregations (max ≥ mean ≥ min).
func (c *Client) Score(ctx context.Context, _probeName, text string) (float64, error) {
	body := analyzeRequest{
		Text:      text,
		BatchSize: c.batchSize,
	}
	reqBytes, err := json.Marshal(body)
	if err != nil {
		return 0, fmt.Errorf("marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(reqBytes))
	if err != nil {
		return 0, fmt.Errorf("build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "text/event-stream")
	if c.apiKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+c.apiKey)
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return 0, fmt.Errorf("transport: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		errBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return 0, fmt.Errorf("bad_response: status %d: %s", resp.StatusCode, string(errBody))
	}

	return parseAnalyzeStream(resp.Body)
}

// parseAnalyzeStream reads SSE events from r until the `analyze_done` event
// arrives, then returns max(probe_probs). Earlier events are skipped. If the
// stream ends before `analyze_done` arrives, returns bad_response.
func parseAnalyzeStream(r io.Reader) (float64, error) {
	scanner := bufio.NewScanner(r)
	// SSE lines can be long; default 64K buffer is enough for one analyze_done
	// payload at typical prompt sizes, but raise the cap so we don't choke on
	// long token arrays.
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	var event string
	var data strings.Builder

	flush := func() (float64, bool, error) {
		if data.Len() == 0 {
			event = ""
			return 0, false, nil
		}
		defer func() {
			event = ""
			data.Reset()
		}()
		// Only `analyze_done` is terminal and carries the full vector.
		if event != "analyze_done" {
			return 0, false, nil
		}
		var ev analyzeDoneEvent
		if err := json.Unmarshal([]byte(data.String()), &ev); err != nil {
			return 0, false, fmt.Errorf("bad_response: parse analyze_done: %w", err)
		}
		if len(ev.ProbeProbs) == 0 {
			// Empty probe_probs (e.g. empty text) is a clear "no signal" — not
			// an error. Return 0 so the spec's clear_threshold can match.
			return 0, true, nil
		}
		max := ev.ProbeProbs[0]
		for _, p := range ev.ProbeProbs[1:] {
			if p > max {
				max = p
			}
		}
		return max, true, nil
	}

	for scanner.Scan() {
		line := scanner.Text()
		// Blank line = event terminator.
		if line == "" {
			score, done, err := flush()
			if err != nil {
				return 0, err
			}
			if done {
				return score, nil
			}
			continue
		}
		if strings.HasPrefix(line, ":") {
			// Comment line — skip.
			continue
		}
		if strings.HasPrefix(line, "event:") {
			event = strings.TrimSpace(line[len("event:"):])
			continue
		}
		if strings.HasPrefix(line, "data:") {
			if data.Len() > 0 {
				data.WriteByte('\n')
			}
			data.WriteString(strings.TrimPrefix(line[len("data:"):], " "))
			continue
		}
		// Other SSE fields (id:, retry:) — ignore.
	}
	// EOF without a trailing blank line: try one final flush.
	if score, done, err := flush(); err != nil {
		return 0, err
	} else if done {
		return score, nil
	}
	if err := scanner.Err(); err != nil {
		return 0, fmt.Errorf("transport: stream read: %w", err)
	}
	return 0, fmt.Errorf("bad_response: stream ended without analyze_done event")
}
