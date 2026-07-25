-- Project-scoped managed Cookie header values. Values remain private and are
-- never returned by ordinary status/list APIs.

CREATE TABLE project_cookies (
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    host TEXT NOT NULL,
    target_url TEXT NOT NULL,
    cookie_header TEXT NOT NULL,
    names_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (project_id, host)
);
