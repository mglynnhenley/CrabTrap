-- Phase 3: probes are now scoped per LLM policy, mirroring how the judge
-- prompt is scoped. The original `probes` table stays as the catalog of
-- available probe heads (and the global fallback for policies that have not
-- yet been migrated to per-policy assignment). New runtime gating decisions
-- consult `policy_probes` first.
--
-- Migration is non-breaking: a policy with zero rows in policy_probes
-- continues to fall back to the rows in `probes`. Operators opt into
-- per-policy probes by inserting rows here for the policy they care about.
CREATE TABLE IF NOT EXISTS policy_probes (
    policy_id        TEXT NOT NULL REFERENCES llm_policies(id) ON DELETE CASCADE,
    probe_name       TEXT NOT NULL REFERENCES probes(name)      ON DELETE RESTRICT,
    enabled          BOOLEAN NOT NULL DEFAULT TRUE,
    threshold        DOUBLE PRECISION NOT NULL,
    clear_threshold  DOUBLE PRECISION,                       -- NULL = no fast-allow opt-in for this policy
    aggregation      TEXT NOT NULL DEFAULT 'max',            -- 'max' | 'mean'
    judge_policy_id  TEXT REFERENCES llm_policies(id),       -- per-policy gray-zone escalation override
    priority         INT  NOT NULL DEFAULT 0,                -- lower fires first; ties broken by probe_name
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (policy_id, probe_name)
);

CREATE INDEX IF NOT EXISTS idx_policy_probes_policy
    ON policy_probes(policy_id, priority, probe_name);
