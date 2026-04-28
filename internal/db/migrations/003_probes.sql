-- Probes are configurable from the admin UI. Each row defines one probe head
-- exposed by the probe-demo endpoint, plus the gating thresholds used at
-- runtime. Phase 1 stores threshold/aggregation/enabled flags; the
-- judge_policy_id column is reserved for Phase 2 per-probe escalation.
CREATE TABLE IF NOT EXISTS probes (
    name             TEXT        PRIMARY KEY,                 -- matches the key in probe-demo's scores map
    enabled          BOOLEAN     NOT NULL DEFAULT FALSE,
    threshold        DOUBLE PRECISION NOT NULL DEFAULT 0.7,   -- aggregated score >= threshold => DENY
    clear_threshold  DOUBLE PRECISION,                        -- nullable; opt-in per probe for AllClear fast-allow
    aggregation      TEXT        NOT NULL DEFAULT 'max',      -- 'max' | 'mean'
    judge_policy_id  TEXT        REFERENCES llm_policies(id), -- Phase 2: per-probe escalation; null = use global judge
    priority         INT         NOT NULL DEFAULT 0,          -- lower fires first; ties broken by name
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_probes_priority ON probes(priority, name);
