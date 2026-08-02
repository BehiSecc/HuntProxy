CREATE TABLE request_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    position INTEGER NOT NULL DEFAULT 0,
    host_pattern TEXT,
    target TEXT NOT NULL,
    operation TEXT NOT NULL,
    header_name TEXT,
    match_kind TEXT NOT NULL,
    pattern TEXT NOT NULL DEFAULT '',
    replacement TEXT,
    replace_all INTEGER NOT NULL DEFAULT 1,
    revision INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX idx_request_rules_project_position
ON request_rules(project_id, enabled, position, id);

CREATE TABLE exchange_request_rules (
    project_id INTEGER NOT NULL,
    exchange_id INTEGER NOT NULL,
    rule_id INTEGER,
    rule_name TEXT NOT NULL,
    PRIMARY KEY(project_id, exchange_id, rule_id),
    FOREIGN KEY(project_id, exchange_id) REFERENCES exchanges(project_id, exchange_id) ON DELETE CASCADE
);
