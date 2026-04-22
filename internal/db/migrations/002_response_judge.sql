ALTER TABLE llm_policies
    ADD COLUMN IF NOT EXISTS response_prompt TEXT NOT NULL DEFAULT '';

ALTER TABLE audit_log
    ADD COLUMN IF NOT EXISTS response_decision        TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS response_llm_response_id TEXT REFERENCES llm_responses(id);

CREATE INDEX IF NOT EXISTS idx_audit_log_response_decision
    ON audit_log(response_decision) WHERE response_decision <> '';
