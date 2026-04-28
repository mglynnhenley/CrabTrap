package probes

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrProbeNotFound is returned by Get/Delete when no row matches the name.
var ErrProbeNotFound = errors.New("probe not found")

// Probe is the persisted configuration for one probe head exposed by
// probe-demo. Name is the primary key and must match the key returned in
// probe-demo's response scores map (derived from the checkpoint filename
// served by the upstream model server). ClearThreshold and JudgePolicyID are
// pointers so a nil value distinguishes "not set" from a zero/empty value
// passed through.
type Probe struct {
	Name           string    `json:"name"`
	Enabled        bool      `json:"enabled"`
	Threshold      float64   `json:"threshold"`
	ClearThreshold *float64  `json:"clear_threshold,omitempty"`
	Aggregation    string    `json:"aggregation"`
	JudgePolicyID  *string   `json:"judge_policy_id,omitempty"`
	Priority       int       `json:"priority"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// UpsertProbeRequest is the editable surface of a probe row. Probes are
// keyed by name (set server-side by the probe-demo checkpoint), so create
// and update collapse to a single upsert call.
type UpsertProbeRequest struct {
	Name           string
	Enabled        bool
	Threshold      float64
	ClearThreshold *float64
	Aggregation    string
	JudgePolicyID  *string
	Priority       int
}

// Store manages probe configuration rows.
//
// The first group is the catalog (Phase 1/2): one row per probe name with
// global gating defaults. The second group is the per-policy attachment
// (Phase 3): each LLM policy carries its own subset of probes with its own
// tuning. ListEnabledForPolicy is the single resolver the runner calls — it
// implements the dual-mode fallback to the global catalog when a policy has
// no rows attached yet.
type Store interface {
	List(ctx context.Context) ([]Probe, error)
	ListEnabled(ctx context.Context) ([]Probe, error)
	Get(ctx context.Context, name string) (*Probe, error)
	Upsert(ctx context.Context, req UpsertProbeRequest) (*Probe, error)
	Delete(ctx context.Context, name string) error

	ListEnabledForPolicy(ctx context.Context, policyID string) ([]Spec, error)
	ListForPolicy(ctx context.Context, policyID string) ([]PolicyProbe, error)
	UpsertForPolicy(ctx context.Context, req UpsertPolicyProbeRequest) (*PolicyProbe, error)
	DeleteForPolicy(ctx context.Context, policyID, probeName string) error
}

// PGStore implements Store backed by Postgres.
type PGStore struct {
	pool *pgxpool.Pool
}

// NewPGStore wraps an existing pool.
func NewPGStore(pool *pgxpool.Pool) *PGStore {
	return &PGStore{pool: pool}
}

const probeSelectCols = `name, enabled, threshold, clear_threshold, aggregation, judge_policy_id, priority, created_at, updated_at`

func scanProbe(row interface {
	Scan(dest ...any) error
}) (*Probe, error) {
	var p Probe
	if err := row.Scan(
		&p.Name, &p.Enabled, &p.Threshold, &p.ClearThreshold,
		&p.Aggregation, &p.JudgePolicyID, &p.Priority,
		&p.CreatedAt, &p.UpdatedAt,
	); err != nil {
		return nil, err
	}
	return &p, nil
}

// List returns every probe row ordered by priority ascending then name.
func (s *PGStore) List(ctx context.Context) ([]Probe, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+probeSelectCols+` FROM probes ORDER BY priority, name`)
	if err != nil {
		return nil, fmt.Errorf("list probes: %w", err)
	}
	defer rows.Close()
	out := []Probe{}
	for rows.Next() {
		p, err := scanProbe(rows)
		if err != nil {
			return nil, fmt.Errorf("list probes scan: %w", err)
		}
		out = append(out, *p)
	}
	return out, rows.Err()
}

// ListEnabled returns only the rows with enabled=TRUE, ordered the same way
// as List. The runner uses this to refresh its in-memory spec slice.
func (s *PGStore) ListEnabled(ctx context.Context) ([]Probe, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+probeSelectCols+` FROM probes WHERE enabled = TRUE ORDER BY priority, name`)
	if err != nil {
		return nil, fmt.Errorf("list enabled probes: %w", err)
	}
	defer rows.Close()
	out := []Probe{}
	for rows.Next() {
		p, err := scanProbe(rows)
		if err != nil {
			return nil, fmt.Errorf("list enabled probes scan: %w", err)
		}
		out = append(out, *p)
	}
	return out, rows.Err()
}

// Get fetches a single probe row by name. Returns ErrProbeNotFound when no
// row matches.
func (s *PGStore) Get(ctx context.Context, name string) (*Probe, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT `+probeSelectCols+` FROM probes WHERE name = $1`, name)
	p, err := scanProbe(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrProbeNotFound
		}
		return nil, fmt.Errorf("get probe %q: %w", name, err)
	}
	return p, nil
}

// validateUpsert canonicalises and bounds-checks an upsert request. The
// constraints mirror those documented on probes.Spec (ClearThreshold opt-in;
// 0 <= clear <= threshold <= 1; aggregation in {max, mean}). It mutates req
// to fill in the default aggregation when the caller leaves it blank.
func validateUpsert(req *UpsertProbeRequest) error {
	if req.Name == "" {
		return errors.New("probe name is required")
	}
	if req.Threshold < 0 || req.Threshold > 1 {
		return fmt.Errorf("threshold must be in [0, 1], got %v", req.Threshold)
	}
	if req.ClearThreshold != nil {
		ct := *req.ClearThreshold
		if ct < 0 || ct > 1 {
			return fmt.Errorf("clear_threshold must be in [0, 1], got %v", ct)
		}
		if ct > req.Threshold {
			return fmt.Errorf("clear_threshold (%v) must be <= threshold (%v)", ct, req.Threshold)
		}
	}
	switch req.Aggregation {
	case "":
		req.Aggregation = AggregationMax
	case AggregationMax, AggregationMean:
		// ok
	default:
		return fmt.Errorf("aggregation must be %q or %q, got %q",
			AggregationMax, AggregationMean, req.Aggregation)
	}
	return nil
}

// Upsert inserts a probe row or replaces every editable column on an
// existing one. The DB-side updated_at is bumped on conflict.
func (s *PGStore) Upsert(ctx context.Context, req UpsertProbeRequest) (*Probe, error) {
	if err := validateUpsert(&req); err != nil {
		return nil, err
	}
	row := s.pool.QueryRow(ctx, `
		INSERT INTO probes(name, enabled, threshold, clear_threshold, aggregation, judge_policy_id, priority)
		VALUES($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (name) DO UPDATE SET
			enabled         = EXCLUDED.enabled,
			threshold       = EXCLUDED.threshold,
			clear_threshold = EXCLUDED.clear_threshold,
			aggregation     = EXCLUDED.aggregation,
			judge_policy_id = EXCLUDED.judge_policy_id,
			priority        = EXCLUDED.priority,
			updated_at      = NOW()
		RETURNING `+probeSelectCols,
		req.Name, req.Enabled, req.Threshold, req.ClearThreshold,
		req.Aggregation, req.JudgePolicyID, req.Priority,
	)
	p, err := scanProbe(row)
	if err != nil {
		return nil, fmt.Errorf("upsert probe %q: %w", req.Name, err)
	}
	return p, nil
}

// SeedIfEmpty inserts the given defaults into the table only when no probe
// rows exist yet. It is the bootstrap path for moving operators off the
// YAML-driven probe list onto the DB-backed admin UI: the first gateway to
// reach this code populates the table; subsequent starts find rows and skip
// the loop. The ON CONFLICT DO NOTHING clause prevents a race between
// concurrent replicas that both observe an empty table at startup. Returns
// the number of rows actually inserted.
func (s *PGStore) SeedIfEmpty(ctx context.Context, defaults []UpsertProbeRequest) (int, error) {
	var n int
	if err := s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM probes`).Scan(&n); err != nil {
		return 0, fmt.Errorf("seed count: %w", err)
	}
	if n > 0 {
		return 0, nil
	}

	inserted := 0
	for _, p := range defaults {
		if err := validateUpsert(&p); err != nil {
			return inserted, fmt.Errorf("seed validate %q: %w", p.Name, err)
		}
		tag, err := s.pool.Exec(ctx, `
			INSERT INTO probes(name, enabled, threshold, clear_threshold, aggregation, judge_policy_id, priority)
			VALUES($1, $2, $3, $4, $5, $6, $7)
			ON CONFLICT (name) DO NOTHING
		`, p.Name, p.Enabled, p.Threshold, p.ClearThreshold, p.Aggregation, p.JudgePolicyID, p.Priority)
		if err != nil {
			return inserted, fmt.Errorf("seed insert %q: %w", p.Name, err)
		}
		if tag.RowsAffected() > 0 {
			inserted++
		}
	}
	return inserted, nil
}

// Delete removes a probe row. Returns ErrProbeNotFound when no row matches.
func (s *PGStore) Delete(ctx context.Context, name string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM probes WHERE name = $1`, name)
	if err != nil {
		return fmt.Errorf("delete probe %q: %w", name, err)
	}
	if tag.RowsAffected() == 0 {
		return ErrProbeNotFound
	}
	return nil
}

// ToSpec converts a persisted Probe row into the runtime Spec consumed by
// Runner.Evaluate. A nil ClearThreshold maps to 0.0, which matches the
// runner's "ClearThreshold==0 disables the AllClear opt-in" semantics.
// A nil JudgePolicyID maps to "" (no per-probe judge override).
func (p *Probe) ToSpec() Spec {
	s := Spec{
		Name:        p.Name,
		Threshold:   p.Threshold,
		Aggregation: p.Aggregation,
	}
	if p.ClearThreshold != nil {
		s.ClearThreshold = *p.ClearThreshold
	}
	if p.JudgePolicyID != nil {
		s.JudgePolicyID = *p.JudgePolicyID
	}
	return s
}

// PolicyProbe is one row in the policy_probes join table — a probe attached
// to an LLM policy with that policy's own tuning. The shape mirrors Probe but
// drops the implicit-default story: every gating column carries an explicit
// value, copied in at attach time. This way changing the catalog default on
// `probes.threshold` does not silently re-tune every policy that already
// attached the probe.
type PolicyProbe struct {
	PolicyID       string    `json:"policy_id"`
	ProbeName      string    `json:"probe_name"`
	Enabled        bool      `json:"enabled"`
	Threshold      float64   `json:"threshold"`
	ClearThreshold *float64  `json:"clear_threshold,omitempty"`
	Aggregation    string    `json:"aggregation"`
	JudgePolicyID  *string   `json:"judge_policy_id,omitempty"`
	Priority       int       `json:"priority"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// UpsertPolicyProbeRequest is the editable surface of a policy_probes row.
// PolicyID and ProbeName together form the natural key.
type UpsertPolicyProbeRequest struct {
	PolicyID       string
	ProbeName      string
	Enabled        bool
	Threshold      float64
	ClearThreshold *float64
	Aggregation    string
	JudgePolicyID  *string
	Priority       int
}

// ToSpec converts a PolicyProbe into the runtime Spec consumed by
// Runner.Evaluate. Mirrors Probe.ToSpec.
func (p *PolicyProbe) ToSpec() Spec {
	s := Spec{
		Name:        p.ProbeName,
		Threshold:   p.Threshold,
		Aggregation: p.Aggregation,
	}
	if p.ClearThreshold != nil {
		s.ClearThreshold = *p.ClearThreshold
	}
	if p.JudgePolicyID != nil {
		s.JudgePolicyID = *p.JudgePolicyID
	}
	return s
}

const policyProbeSelectCols = `policy_id, probe_name, enabled, threshold, clear_threshold, aggregation, judge_policy_id, priority, created_at, updated_at`

func scanPolicyProbe(row interface {
	Scan(dest ...any) error
}) (*PolicyProbe, error) {
	var p PolicyProbe
	if err := row.Scan(
		&p.PolicyID, &p.ProbeName, &p.Enabled, &p.Threshold, &p.ClearThreshold,
		&p.Aggregation, &p.JudgePolicyID, &p.Priority,
		&p.CreatedAt, &p.UpdatedAt,
	); err != nil {
		return nil, err
	}
	return &p, nil
}

// ListForPolicy returns every policy_probes row for the given policy,
// ordered by priority then probe_name. The admin UI uses this to render the
// "what's attached to this policy" view. Returns an empty slice (not error)
// when the policy has no rows.
func (s *PGStore) ListForPolicy(ctx context.Context, policyID string) ([]PolicyProbe, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+policyProbeSelectCols+`
		FROM policy_probes
		WHERE policy_id = $1
		ORDER BY priority, probe_name`, policyID)
	if err != nil {
		return nil, fmt.Errorf("list policy_probes for %q: %w", policyID, err)
	}
	defer rows.Close()
	out := []PolicyProbe{}
	for rows.Next() {
		p, err := scanPolicyProbe(rows)
		if err != nil {
			return nil, fmt.Errorf("list policy_probes scan: %w", err)
		}
		out = append(out, *p)
	}
	return out, rows.Err()
}

// ListEnabledForPolicy is the runtime resolver consulted by the runner. It
// implements the dual-mode fallback: when the policy has at least one row in
// policy_probes, only the enabled rows for that policy are returned;
// otherwise the global ListEnabled rows are returned so policies that pre-date
// Phase 3 keep working unchanged.
//
// Passing an empty policyID short-circuits to global ListEnabled (callers
// without a resolved policy still get the legacy gating behaviour).
func (s *PGStore) ListEnabledForPolicy(ctx context.Context, policyID string) ([]Spec, error) {
	if policyID == "" {
		return s.listEnabledGlobal(ctx)
	}

	// Fast count to choose the path. policy_probes is small per policy
	// (admin-edited), so an extra scalar query is cheap and avoids two
	// SELECTs when the policy has no rows.
	var n int
	if err := s.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM policy_probes WHERE policy_id = $1`, policyID,
	).Scan(&n); err != nil {
		return nil, fmt.Errorf("count policy_probes for %q: %w", policyID, err)
	}
	if n == 0 {
		return s.listEnabledGlobal(ctx)
	}

	rows, err := s.pool.Query(ctx, `SELECT `+policyProbeSelectCols+`
		FROM policy_probes
		WHERE policy_id = $1 AND enabled = TRUE
		ORDER BY priority, probe_name`, policyID)
	if err != nil {
		return nil, fmt.Errorf("list enabled policy_probes for %q: %w", policyID, err)
	}
	defer rows.Close()
	out := []Spec{}
	for rows.Next() {
		p, err := scanPolicyProbe(rows)
		if err != nil {
			return nil, fmt.Errorf("list enabled policy_probes scan: %w", err)
		}
		out = append(out, p.ToSpec())
	}
	return out, rows.Err()
}

// listEnabledGlobal is the Phase 1/2 path: read enabled rows from the
// catalog table directly. Kept private; callers go through ListEnabledForPolicy.
func (s *PGStore) listEnabledGlobal(ctx context.Context) ([]Spec, error) {
	probes, err := s.ListEnabled(ctx)
	if err != nil {
		return nil, err
	}
	specs := make([]Spec, 0, len(probes))
	for i := range probes {
		specs = append(specs, probes[i].ToSpec())
	}
	return specs, nil
}

// validatePolicyProbeUpsert mirrors validateUpsert for the policy_probes
// shape. Same numeric bounds, same aggregation whitelist.
func validatePolicyProbeUpsert(req *UpsertPolicyProbeRequest) error {
	if req.PolicyID == "" {
		return errors.New("policy_id is required")
	}
	if req.ProbeName == "" {
		return errors.New("probe_name is required")
	}
	if req.Threshold < 0 || req.Threshold > 1 {
		return fmt.Errorf("threshold must be in [0, 1], got %v", req.Threshold)
	}
	if req.ClearThreshold != nil {
		ct := *req.ClearThreshold
		if ct < 0 || ct > 1 {
			return fmt.Errorf("clear_threshold must be in [0, 1], got %v", ct)
		}
		if ct > req.Threshold {
			return fmt.Errorf("clear_threshold (%v) must be <= threshold (%v)", ct, req.Threshold)
		}
	}
	switch req.Aggregation {
	case "":
		req.Aggregation = AggregationMax
	case AggregationMax, AggregationMean:
		// ok
	default:
		return fmt.Errorf("aggregation must be %q or %q, got %q",
			AggregationMax, AggregationMean, req.Aggregation)
	}
	return nil
}

// UpsertForPolicy attaches a probe to a policy or replaces every editable
// column on an existing attachment. Returns the resulting row.
func (s *PGStore) UpsertForPolicy(ctx context.Context, req UpsertPolicyProbeRequest) (*PolicyProbe, error) {
	if err := validatePolicyProbeUpsert(&req); err != nil {
		return nil, err
	}
	row := s.pool.QueryRow(ctx, `
		INSERT INTO policy_probes(policy_id, probe_name, enabled, threshold, clear_threshold, aggregation, judge_policy_id, priority)
		VALUES($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (policy_id, probe_name) DO UPDATE SET
			enabled         = EXCLUDED.enabled,
			threshold       = EXCLUDED.threshold,
			clear_threshold = EXCLUDED.clear_threshold,
			aggregation     = EXCLUDED.aggregation,
			judge_policy_id = EXCLUDED.judge_policy_id,
			priority        = EXCLUDED.priority,
			updated_at      = NOW()
		RETURNING `+policyProbeSelectCols,
		req.PolicyID, req.ProbeName, req.Enabled, req.Threshold, req.ClearThreshold,
		req.Aggregation, req.JudgePolicyID, req.Priority,
	)
	p, err := scanPolicyProbe(row)
	if err != nil {
		return nil, fmt.Errorf("upsert policy_probes (%q, %q): %w", req.PolicyID, req.ProbeName, err)
	}
	return p, nil
}

// DeleteForPolicy detaches a probe from a policy. Returns ErrProbeNotFound
// when no row matches.
func (s *PGStore) DeleteForPolicy(ctx context.Context, policyID, probeName string) error {
	tag, err := s.pool.Exec(ctx,
		`DELETE FROM policy_probes WHERE policy_id = $1 AND probe_name = $2`,
		policyID, probeName)
	if err != nil {
		return fmt.Errorf("delete policy_probes (%q, %q): %w", policyID, probeName, err)
	}
	if tag.RowsAffected() == 0 {
		return ErrProbeNotFound
	}
	return nil
}
