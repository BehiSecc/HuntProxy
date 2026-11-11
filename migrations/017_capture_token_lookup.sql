-- SHA-256 of the capture token, so proxy authentication can find its session
-- by index instead of recomputing a salted hash for every active row. Sessions
-- created before this migration keep a NULL lookup (their tokens are not
-- recoverable) and are still authenticated through the partial legacy index.
ALTER TABLE capture_sessions ADD COLUMN token_lookup BLOB;

CREATE INDEX idx_capture_sessions_token_lookup
    ON capture_sessions(token_lookup) WHERE token_lookup IS NOT NULL;

CREATE INDEX idx_capture_sessions_legacy_active
    ON capture_sessions(id) WHERE token_lookup IS NULL AND status = 'active';
