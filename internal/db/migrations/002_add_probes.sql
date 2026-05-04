-- Linear probes (pre-judge security layer): per-policy probe attachments and audit-log persistence.
-- Idempotent: ADD COLUMN IF NOT EXISTS so the migration is safe to re-run.

ALTER TABLE llm_policies
    ADD COLUMN IF NOT EXISTS probes JSONB NOT NULL DEFAULT '[]'::jsonb;

ALTER TABLE audit_log
    ADD COLUMN IF NOT EXISTS probe_response_json JSONB;
