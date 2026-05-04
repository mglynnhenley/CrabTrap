//go:build modal

package probes

import (
	"context"
	"testing"
	"time"
)

// TestIntegration_Modal hits the live Modal hallucination probe service.
// Gated behind the `modal` build tag so it only runs when explicitly invoked
// with `go test -tags modal ./internal/probes/...`. This test exists so we
// can validate the SSE wire shape against reality without burdening CI.
func TestIntegration_Modal(t *testing.T) {
	const endpoint = "https://telluvian-71910--hallucination-probe-backend-analyze-stream.modal.run"
	c := NewClient(endpoint, "", 8)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	score, err := c.Score(ctx, "hallucination",
		"The capital of France is Paris. The Eiffel Tower stands 1500 meters tall and was made of solid gold.")
	if err != nil {
		t.Fatalf("Score: %v", err)
	}
	if score < 0 || score > 1 {
		t.Errorf("score out of [0,1]: %v", score)
	}
	t.Logf("Modal hallucination probe score = %.4f", score)
}
