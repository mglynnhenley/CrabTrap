package admin

import (
	"errors"
	"net/http"
	"strings"

	"github.com/brexhq/CrabTrap/internal/probes"
)

// handlePolicyProbes services Phase 3 per-policy probe assignments under
// /admin/llm-policies/{policyID}/probes. Routed from handleLLMPolicyAction so
// it shares the policy_id parsing + admin gate. The "action" string is the
// caller-parsed remainder of the URL path after the policy id (e.g. "probes"
// or "probes/financial_advice").
func (a *API) handlePolicyProbes(w http.ResponseWriter, r *http.Request, policyID, action string) {
	if a.probesStore == nil {
		http.Error(w, "probes store not configured", http.StatusServiceUnavailable)
		return
	}

	switch {
	case r.Method == http.MethodGet && action == "probes":
		rows, err := a.probesStore.ListForPolicy(r.Context(), policyID)
		if err != nil {
			respondError(w, http.StatusInternalServerError, "failed to list policy probes", err)
			return
		}
		respondJSON(w, http.StatusOK, rows)

	case r.Method == http.MethodPut && action == "probes":
		// Upsert one attachment. probe_name comes in the body so a single
		// endpoint covers both attach and re-tune.
		limitBody(w, r, maxBodySize)
		var body struct {
			ProbeName      string   `json:"probe_name"`
			Enabled        bool     `json:"enabled"`
			Threshold      float64  `json:"threshold"`
			ClearThreshold *float64 `json:"clear_threshold"`
			Aggregation    string   `json:"aggregation"`
			JudgePolicyID  *string  `json:"judge_policy_id"`
			Priority       int      `json:"priority"`
		}
		if !decodeBody(w, r, &body) {
			return
		}
		if body.ProbeName == "" {
			http.Error(w, "probe_name is required", http.StatusBadRequest)
			return
		}
		// "" judge_policy_id means "clear the link" — keep null in the FK column.
		if body.JudgePolicyID != nil && *body.JudgePolicyID == "" {
			body.JudgePolicyID = nil
		}
		updated, err := a.probesStore.UpsertForPolicy(r.Context(), probes.UpsertPolicyProbeRequest{
			PolicyID:       policyID,
			ProbeName:      body.ProbeName,
			Enabled:        body.Enabled,
			Threshold:      body.Threshold,
			ClearThreshold: body.ClearThreshold,
			Aggregation:    body.Aggregation,
			JudgePolicyID:  body.JudgePolicyID,
			Priority:       body.Priority,
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		respondJSON(w, http.StatusOK, updated)

	case r.Method == http.MethodDelete && strings.HasPrefix(action, "probes/"):
		probeName := strings.TrimPrefix(action, "probes/")
		if probeName == "" || strings.Contains(probeName, "/") {
			http.Error(w, "missing or invalid probe name", http.StatusBadRequest)
			return
		}
		if err := a.probesStore.DeleteForPolicy(r.Context(), policyID, probeName); err != nil {
			if errors.Is(err, probes.ErrProbeNotFound) {
				http.Error(w, "policy probe attachment not found", http.StatusNotFound)
				return
			}
			respondError(w, http.StatusInternalServerError, "failed to detach policy probe", err)
			return
		}
		w.WriteHeader(http.StatusNoContent)

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleProbes services GET (list) for /admin/probes. Per-probe writes go
// through the {name}-suffixed handler so the URL identifies the row and PUT
// is idempotent.
func (a *API) handleProbes(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.requireAdmin(w, r); !ok {
		return
	}
	if a.probesStore == nil {
		http.Error(w, "probes store not configured", http.StatusServiceUnavailable)
		return
	}

	switch r.Method {
	case http.MethodGet:
		rows, err := a.probesStore.List(r.Context())
		if err != nil {
			respondError(w, http.StatusInternalServerError, "failed to list probes", err)
			return
		}
		respondJSON(w, http.StatusOK, rows)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleProbeDiscover services POST /admin/probes/discover. It calls the
// upstream probe-demo with a minimal completion and returns the probe
// names it exposes — used by the admin UI's "add probe" flow so admins
// don't have to type names by hand. The discovery call is gated by admin
// auth so anonymous callers can't burn probe-demo capacity.
func (a *API) handleProbeDiscover(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.requireAdmin(w, r); !ok {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if a.probeDiscoverer == nil {
		http.Error(w, "probe discovery not configured", http.StatusServiceUnavailable)
		return
	}
	names, err := a.probeDiscoverer.Discover(r.Context())
	if err != nil {
		respondError(w, http.StatusBadGateway, "probe discovery failed", err)
		return
	}
	respondJSON(w, http.StatusOK, map[string]any{"names": names})
}

// handleProbeAction services GET/PUT/DELETE for /admin/probes/{name}. Probe
// names come from probe-demo's scores map, so admins identify rows by that
// natural key rather than a generated ID.
func (a *API) handleProbeAction(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.requireAdmin(w, r); !ok {
		return
	}
	if a.probesStore == nil {
		http.Error(w, "probes store not configured", http.StatusServiceUnavailable)
		return
	}

	name := strings.TrimPrefix(r.URL.Path, "/admin/probes/")
	if name == "" || strings.Contains(name, "/") {
		http.Error(w, "missing or invalid probe name", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodGet:
		p, err := a.probesStore.Get(r.Context(), name)
		if err != nil {
			if errors.Is(err, probes.ErrProbeNotFound) {
				http.Error(w, "probe not found", http.StatusNotFound)
				return
			}
			respondError(w, http.StatusInternalServerError, "failed to get probe", err)
			return
		}
		respondJSON(w, http.StatusOK, p)

	case http.MethodPut:
		limitBody(w, r, maxBodySize)
		var body struct {
			Enabled        bool     `json:"enabled"`
			Threshold      float64  `json:"threshold"`
			ClearThreshold *float64 `json:"clear_threshold"`
			Aggregation    string   `json:"aggregation"`
			JudgePolicyID  *string  `json:"judge_policy_id"`
			Priority       int      `json:"priority"`
		}
		if !decodeBody(w, r, &body) {
			return
		}
		// An empty judge_policy_id string means "clear the link" — translate
		// that to nil so the FK-bearing column gets NULL rather than ''.
		if body.JudgePolicyID != nil && *body.JudgePolicyID == "" {
			body.JudgePolicyID = nil
		}
		updated, err := a.probesStore.Upsert(r.Context(), probes.UpsertProbeRequest{
			Name:           name,
			Enabled:        body.Enabled,
			Threshold:      body.Threshold,
			ClearThreshold: body.ClearThreshold,
			Aggregation:    body.Aggregation,
			JudgePolicyID:  body.JudgePolicyID,
			Priority:       body.Priority,
		})
		if err != nil {
			// validateUpsert errors are caller-input problems; surface as 400.
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		respondJSON(w, http.StatusOK, updated)

	case http.MethodDelete:
		if err := a.probesStore.Delete(r.Context(), name); err != nil {
			if errors.Is(err, probes.ErrProbeNotFound) {
				http.Error(w, "probe not found", http.StatusNotFound)
				return
			}
			respondError(w, http.StatusInternalServerError, "failed to delete probe", err)
			return
		}
		w.WriteHeader(http.StatusNoContent)

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}
