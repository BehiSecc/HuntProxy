-- Tie JavaScript resources to the page that included or loaded them.

CREATE TABLE javascript_provenance (
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    javascript_url TEXT NOT NULL,
    javascript_host TEXT NOT NULL,
    javascript_path TEXT NOT NULL,
    source_page_url TEXT NOT NULL,
    source_page_host TEXT NOT NULL,
    browser_session_id INTEGER,
    discovery_kind TEXT NOT NULL CHECK (discovery_kind IN ('browser', 'source')),
    created_at TEXT NOT NULL,
    PRIMARY KEY (project_id, javascript_url, source_page_url)
);

CREATE INDEX idx_javascript_provenance_source
    ON javascript_provenance(project_id, source_page_host, javascript_url);
CREATE INDEX idx_javascript_provenance_resource
    ON javascript_provenance(project_id, javascript_host, javascript_url);
