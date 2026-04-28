package probes_test

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/brexhq/CrabTrap/internal/db"
	"github.com/brexhq/CrabTrap/internal/dbtest"
	"github.com/brexhq/CrabTrap/internal/probes"
)

var testPool *pgxpool.Pool

func TestMain(m *testing.M) {
	// runner_test.go in this package has tests that don't need a database
	// (httptest server only). When dbtest.Setup fails (Docker missing) or
	// the testcontainers init panics, leave testPool nil so DB-backed tests
	// skip via the t.Skip("no test database") guard while the in-memory
	// runner tests still execute.
	cleanup := tryDBSetup()
	code := m.Run()
	if cleanup != nil {
		cleanup()
	}
	os.Exit(code)
}

func tryDBSetup() func() {
	defer func() {
		if r := recover(); r != nil {
			slog.Warn("probes TestMain: db setup panicked; DB tests will skip", "panic", r)
		}
	}()
	pool, cleanup, err := dbtest.Setup()
	if err != nil {
		slog.Warn("probes TestMain: db setup failed; DB tests will skip", "error", err)
		return nil
	}
	testPool = pool
	return cleanup
}

// truncate clears the tables touched by these tests. policy_probes is wiped
// directly because nothing CASCADEs from llm_policies → policy_probes, and
// probes can stay between tests since it's a small bounded catalog.
func truncate(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	testPool.Exec(ctx, "TRUNCATE policy_probes")
	testPool.Exec(ctx, "TRUNCATE probes CASCADE")
	testPool.Exec(ctx, "TRUNCATE llm_policies CASCADE")
}

func newStore(t *testing.T) *probes.PGStore {
	t.Helper()
	truncate(t)
	return probes.NewPGStore(testPool)
}

func seedPolicy(t *testing.T) string {
	t.Helper()
	id := db.NewID("llmpol")
	_, err := testPool.Exec(context.Background(), `
		INSERT INTO llm_policies(id, name, prompt, provider, model)
		VALUES($1, 'test-policy', '', '', '')
	`, id)
	if err != nil {
		t.Fatalf("seedPolicy: %v", err)
	}
	return id
}

// seedProbe inserts into the catalog table — required because policy_probes
// has a FK on probes(name).
func seedProbe(t *testing.T, s *probes.PGStore, name string, enabled bool, threshold float64) {
	t.Helper()
	if _, err := s.Upsert(context.Background(), probes.UpsertProbeRequest{
		Name:        name,
		Enabled:     enabled,
		Threshold:   threshold,
		Aggregation: "max",
	}); err != nil {
		t.Fatalf("seedProbe(%q): %v", name, err)
	}
}

// ---- ListEnabledForPolicy ----

func TestListEnabledForPolicy_EmptyPolicyID_FallsBackToGlobal(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	s := newStore(t)
	seedProbe(t, s, "global_a", true, 0.5)
	seedProbe(t, s, "global_b", false, 0.5) // disabled — must be filtered

	specs, err := s.ListEnabledForPolicy(context.Background(), "")
	if err != nil {
		t.Fatalf("ListEnabledForPolicy: %v", err)
	}
	if len(specs) != 1 || specs[0].Name != "global_a" {
		t.Errorf("want [global_a], got %+v", specs)
	}
}

func TestListEnabledForPolicy_PolicyWithNoRows_FallsBackToGlobal(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	s := newStore(t)
	seedProbe(t, s, "global_a", true, 0.5)
	policyID := seedPolicy(t) // no policy_probes rows attached

	specs, err := s.ListEnabledForPolicy(context.Background(), policyID)
	if err != nil {
		t.Fatalf("ListEnabledForPolicy: %v", err)
	}
	if len(specs) != 1 || specs[0].Name != "global_a" {
		t.Errorf("want fallback to global, got %+v", specs)
	}
}

func TestListEnabledForPolicy_PolicyWithRows_ReturnsPolicyOnly(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	s := newStore(t)
	// Catalog has both probes; the policy attaches only one.
	seedProbe(t, s, "shared_probe", true, 0.5)
	seedProbe(t, s, "other_probe", true, 0.5)
	policyID := seedPolicy(t)

	if _, err := s.UpsertForPolicy(context.Background(), probes.UpsertPolicyProbeRequest{
		PolicyID:    policyID,
		ProbeName:   "shared_probe",
		Enabled:     true,
		Threshold:   0.7, // overrides catalog default to prove we read policy_probes
		Aggregation: "max",
	}); err != nil {
		t.Fatalf("UpsertForPolicy: %v", err)
	}

	specs, err := s.ListEnabledForPolicy(context.Background(), policyID)
	if err != nil {
		t.Fatalf("ListEnabledForPolicy: %v", err)
	}
	if len(specs) != 1 {
		t.Fatalf("want 1 spec, got %d (%+v)", len(specs), specs)
	}
	if specs[0].Name != "shared_probe" {
		t.Errorf("want shared_probe, got %q", specs[0].Name)
	}
	if specs[0].Threshold != 0.7 {
		t.Errorf("want policy-scoped threshold 0.7, got %v (catalog default leaked through)", specs[0].Threshold)
	}
}

func TestListEnabledForPolicy_FiltersDisabledRows(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	s := newStore(t)
	seedProbe(t, s, "p1", true, 0.5)
	seedProbe(t, s, "p2", true, 0.5)
	policyID := seedPolicy(t)

	// p1 is disabled at the policy level; should not appear.
	if _, err := s.UpsertForPolicy(context.Background(), probes.UpsertPolicyProbeRequest{
		PolicyID: policyID, ProbeName: "p1", Enabled: false, Threshold: 0.5,
	}); err != nil {
		t.Fatalf("UpsertForPolicy p1: %v", err)
	}
	if _, err := s.UpsertForPolicy(context.Background(), probes.UpsertPolicyProbeRequest{
		PolicyID: policyID, ProbeName: "p2", Enabled: true, Threshold: 0.5,
	}); err != nil {
		t.Fatalf("UpsertForPolicy p2: %v", err)
	}

	specs, err := s.ListEnabledForPolicy(context.Background(), policyID)
	if err != nil {
		t.Fatalf("ListEnabledForPolicy: %v", err)
	}
	if len(specs) != 1 || specs[0].Name != "p2" {
		t.Errorf("want only [p2] (enabled), got %+v", specs)
	}
}

func TestListEnabledForPolicy_OrderedByPriority(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	s := newStore(t)
	seedProbe(t, s, "alpha", true, 0.5)
	seedProbe(t, s, "beta", true, 0.5)
	seedProbe(t, s, "gamma", true, 0.5)
	policyID := seedPolicy(t)

	// Attach in name order but with non-monotonic priorities; result must
	// come back in priority order.
	for _, row := range []struct {
		name     string
		priority int
	}{
		{"alpha", 30},
		{"beta", 10},
		{"gamma", 20},
	} {
		if _, err := s.UpsertForPolicy(context.Background(), probes.UpsertPolicyProbeRequest{
			PolicyID: policyID, ProbeName: row.name, Enabled: true, Threshold: 0.5,
			Priority: row.priority,
		}); err != nil {
			t.Fatalf("UpsertForPolicy(%s): %v", row.name, err)
		}
	}

	specs, err := s.ListEnabledForPolicy(context.Background(), policyID)
	if err != nil {
		t.Fatalf("ListEnabledForPolicy: %v", err)
	}
	got := []string{specs[0].Name, specs[1].Name, specs[2].Name}
	want := []string{"beta", "gamma", "alpha"}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("specs[%d] = %q, want %q (full order: %v)", i, got[i], want[i], got)
		}
	}
}

// ---- UpsertForPolicy ----

func TestUpsertForPolicy_InsertsThenUpdatesOnConflict(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	s := newStore(t)
	seedProbe(t, s, "p1", true, 0.5)
	policyID := seedPolicy(t)

	first, err := s.UpsertForPolicy(context.Background(), probes.UpsertPolicyProbeRequest{
		PolicyID: policyID, ProbeName: "p1", Enabled: true, Threshold: 0.4,
	})
	if err != nil {
		t.Fatalf("first upsert: %v", err)
	}
	if first.Threshold != 0.4 {
		t.Errorf("first.Threshold = %v, want 0.4", first.Threshold)
	}

	second, err := s.UpsertForPolicy(context.Background(), probes.UpsertPolicyProbeRequest{
		PolicyID: policyID, ProbeName: "p1", Enabled: true, Threshold: 0.9,
	})
	if err != nil {
		t.Fatalf("second upsert: %v", err)
	}
	if second.Threshold != 0.9 {
		t.Errorf("second.Threshold = %v, want 0.9 (conflict update did not stick)", second.Threshold)
	}
	if !second.UpdatedAt.After(first.UpdatedAt) {
		t.Errorf("UpdatedAt did not advance on conflict update: first=%v second=%v", first.UpdatedAt, second.UpdatedAt)
	}
}

func TestUpsertForPolicy_RejectsOutOfBoundsThreshold(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	s := newStore(t)
	seedProbe(t, s, "p1", true, 0.5)
	policyID := seedPolicy(t)

	if _, err := s.UpsertForPolicy(context.Background(), probes.UpsertPolicyProbeRequest{
		PolicyID: policyID, ProbeName: "p1", Threshold: 1.5,
	}); err == nil {
		t.Error("expected validation error for threshold > 1, got nil")
	}
}

func TestUpsertForPolicy_RequiresPolicyAndProbeName(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	s := newStore(t)
	seedProbe(t, s, "p1", true, 0.5)
	policyID := seedPolicy(t)

	if _, err := s.UpsertForPolicy(context.Background(), probes.UpsertPolicyProbeRequest{
		ProbeName: "p1", Threshold: 0.5,
	}); err == nil {
		t.Error("expected error for missing policy_id, got nil")
	}

	if _, err := s.UpsertForPolicy(context.Background(), probes.UpsertPolicyProbeRequest{
		PolicyID: policyID, Threshold: 0.5,
	}); err == nil {
		t.Error("expected error for missing probe_name, got nil")
	}
}

// ---- DeleteForPolicy ----

func TestDeleteForPolicy_RemovesRow(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	s := newStore(t)
	seedProbe(t, s, "p1", true, 0.5)
	policyID := seedPolicy(t)
	if _, err := s.UpsertForPolicy(context.Background(), probes.UpsertPolicyProbeRequest{
		PolicyID: policyID, ProbeName: "p1", Enabled: true, Threshold: 0.5,
	}); err != nil {
		t.Fatalf("attach: %v", err)
	}

	if err := s.DeleteForPolicy(context.Background(), policyID, "p1"); err != nil {
		t.Fatalf("DeleteForPolicy: %v", err)
	}

	rows, err := s.ListForPolicy(context.Background(), policyID)
	if err != nil {
		t.Fatalf("ListForPolicy: %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("policy still has %d attachments after delete", len(rows))
	}
}

func TestDeleteForPolicy_NotFound(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	s := newStore(t)
	policyID := seedPolicy(t)

	err := s.DeleteForPolicy(context.Background(), policyID, "no_such_probe")
	if !errors.Is(err, probes.ErrProbeNotFound) {
		t.Errorf("want ErrProbeNotFound, got %v", err)
	}
}

// ---- ListForPolicy ----

func TestListForPolicy_EmptyReturnsEmptySlice(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	s := newStore(t)
	policyID := seedPolicy(t)

	rows, err := s.ListForPolicy(context.Background(), policyID)
	if err != nil {
		t.Fatalf("ListForPolicy: %v", err)
	}
	if rows == nil {
		t.Error("want empty slice, got nil")
	}
	if len(rows) != 0 {
		t.Errorf("want 0 rows, got %d", len(rows))
	}
}

func TestListForPolicy_IncludesDisabledRows(t *testing.T) {
	// ListForPolicy is the admin-UI surface — admins need to see disabled
	// attachments so they can re-enable them. This test would fail if a
	// future refactor accidentally added an `enabled = TRUE` filter.
	if testPool == nil {
		t.Skip("no test database")
	}
	s := newStore(t)
	seedProbe(t, s, "p1", true, 0.5)
	policyID := seedPolicy(t)

	if _, err := s.UpsertForPolicy(context.Background(), probes.UpsertPolicyProbeRequest{
		PolicyID: policyID, ProbeName: "p1", Enabled: false, Threshold: 0.5,
	}); err != nil {
		t.Fatalf("attach disabled: %v", err)
	}

	rows, err := s.ListForPolicy(context.Background(), policyID)
	if err != nil {
		t.Fatalf("ListForPolicy: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("want 1 row, got %d", len(rows))
	}
	if rows[0].Enabled {
		t.Errorf("want Enabled=false in stored row, got true")
	}
}
