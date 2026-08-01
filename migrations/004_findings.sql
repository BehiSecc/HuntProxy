-- Project findings linked to immutable request/response evidence.

CREATE TABLE findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL,
    exchange_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (project_id, exchange_id)
        REFERENCES exchanges(project_id, exchange_id) ON DELETE CASCADE
);

CREATE INDEX idx_findings_project ON findings(project_id, id DESC);
CREATE INDEX idx_findings_exchange ON findings(project_id, exchange_id);
