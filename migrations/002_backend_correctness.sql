-- History/fuzzer/annotation persistence improvements.

ALTER TABLE fuzz_jobs ADD COLUMN error TEXT;

ALTER TABLE fuzz_cases ADD COLUMN state TEXT NOT NULL DEFAULT 'queued';
ALTER TABLE fuzz_cases ADD COLUMN payloads_json TEXT NOT NULL DEFAULT '[]';
ALTER TABLE fuzz_cases ADD COLUMN response_length INTEGER;
ALTER TABLE fuzz_cases ADD COLUMN duration_ms INTEGER;
ALTER TABLE fuzz_cases ADD COLUMN created_at TEXT;
ALTER TABLE fuzz_cases ADD COLUMN started_at TEXT;
ALTER TABLE fuzz_cases ADD COLUMN finished_at TEXT;

CREATE INDEX idx_fuzz_cases_job_case ON fuzz_cases(job_id, case_index DESC);
CREATE INDEX idx_exchange_labels_exchange ON exchange_labels(project_id, exchange_id);

-- Schema v1 did not enforce one annotation per exchange. Preserve the newest
-- row if an early build created duplicates before adding the invariant.
DELETE FROM annotations
WHERE id NOT IN (
    SELECT MAX(id)
    FROM annotations
    GROUP BY project_id, exchange_id
);
CREATE UNIQUE INDEX idx_annotations_exchange ON annotations(project_id, exchange_id);
