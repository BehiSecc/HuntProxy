-- Supporting index for exact, metadata-only fuzz response grouping.
CREATE INDEX idx_fuzz_case_groups
ON fuzz_cases(job_id, state, status_code, body_hash, response_length);
