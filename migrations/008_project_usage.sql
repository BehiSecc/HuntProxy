-- Transactional project usage counters avoid scanning all history for every
-- new exchange. The accounting formula matches the quota estimator.
CREATE TABLE project_usage (
    project_id INTEGER PRIMARY KEY REFERENCES projects(id) ON DELETE CASCADE,
    exchange_count INTEGER NOT NULL DEFAULT 0 CHECK (exchange_count >= 0),
    request_body_bytes INTEGER NOT NULL DEFAULT 0 CHECK (request_body_bytes >= 0),
    response_body_bytes INTEGER NOT NULL DEFAULT 0 CHECK (response_body_bytes >= 0),
    header_bytes INTEGER NOT NULL DEFAULT 0 CHECK (header_bytes >= 0),
    accounted_bytes INTEGER NOT NULL DEFAULT 0 CHECK (accounted_bytes >= 0),
    updated_at TEXT NOT NULL
);

INSERT INTO project_usage (
    project_id, exchange_count, request_body_bytes, response_body_bytes,
    header_bytes, accounted_bytes, updated_at
)
SELECT
    p.id,
    COALESCE(e.exchange_count, 0),
    COALESCE(e.request_body_bytes, 0),
    COALESCE(e.response_body_bytes, 0),
    COALESCE(h.header_bytes, 0),
    COALESCE(e.accounted_bytes, 0) + COALESCE(h.accounted_bytes, 0),
    strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
FROM projects p
LEFT JOIN (
    SELECT project_id,
           COUNT(*) AS exchange_count,
           COALESCE(SUM(COALESCE(request_length, 0)), 0) AS request_body_bytes,
           COALESCE(SUM(COALESCE(response_length, 0)), 0) AS response_body_bytes,
           COALESCE(SUM(
               512 + COALESCE(request_length, 0) + COALESCE(response_length, 0)
               + length(CAST(protocol AS BLOB))
               + length(CAST(method AS BLOB))
               + length(CAST(scheme AS BLOB))
               + length(CAST(authority AS BLOB))
               + length(CAST(host AS BLOB))
               + length(CAST(path AS BLOB))
               + COALESCE(length(CAST(query AS BLOB)), 0)
               + COALESCE(length(CAST(mime AS BLOB)), 0)
               + COALESCE(length(CAST(transport_profile AS BLOB)), 0)
               + COALESCE(length(CAST(page_title AS BLOB)), 0)
               + COALESCE(length(CAST(error_message AS BLOB)), 0)
           ), 0) AS accounted_bytes
    FROM exchanges GROUP BY project_id
) e ON e.project_id = p.id
LEFT JOIN (
    SELECT project_id,
           COALESCE(SUM(length(CAST(name AS BLOB)) + length(value)), 0) AS header_bytes,
           COALESCE(SUM(64 + length(CAST(name AS BLOB)) + length(value)), 0) AS accounted_bytes
    FROM message_headers GROUP BY project_id
) h ON h.project_id = p.id;
