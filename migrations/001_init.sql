-- bb schema v1
PRAGMA foreign_keys = ON;

CREATE TABLE projects (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    scope_json TEXT NOT NULL,
    limits_json TEXT NOT NULL,
    default_browser_profile TEXT NOT NULL DEFAULT 'default',
    noise_policy TEXT NOT NULL DEFAULT 'default'
);

CREATE TABLE capture_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    browser_session_id INTEGER,
    browser_action_id INTEGER,
    created_at TEXT NOT NULL,
    expires_at TEXT,
    revoked_at TEXT,
    status TEXT NOT NULL,
    is_browser_bound INTEGER NOT NULL DEFAULT 0,
    token_hash BLOB NOT NULL,
    token_salt BLOB NOT NULL
);

CREATE INDEX idx_capture_sessions_project ON capture_sessions(project_id, status);

CREATE TABLE bodies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sha256 TEXT NOT NULL,
    original_length INTEGER NOT NULL,
    stored_length INTEGER NOT NULL,
    codec TEXT NOT NULL DEFAULT 'raw',
    mime_class TEXT,
    content BLOB NOT NULL
);

CREATE INDEX idx_bodies_sha ON bodies(sha256);

CREATE TABLE exchanges (
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    exchange_id INTEGER NOT NULL,
    source TEXT NOT NULL,
    started_at TEXT NOT NULL,
    duration_ms INTEGER,
    protocol TEXT NOT NULL DEFAULT 'HTTP/1.1',
    method TEXT NOT NULL,
    scheme TEXT NOT NULL,
    authority TEXT NOT NULL,
    host TEXT NOT NULL,
    port INTEGER NOT NULL,
    path TEXT NOT NULL,
    query TEXT,
    status_code INTEGER,
    mime TEXT,
    request_length INTEGER,
    response_length INTEGER,
    completion TEXT NOT NULL,
    capture_quality TEXT NOT NULL,
    header_representation TEXT NOT NULL,
    body_representation TEXT NOT NULL,
    cache_provenance TEXT NOT NULL DEFAULT 'unknown',
    transport_provenance TEXT,
    transport_profile TEXT,
    page_title TEXT,
    display_title TEXT,
    parent_exchange_id INTEGER,
    redirect_parent_id INTEGER,
    reply_tab_id INTEGER,
    fuzz_job_id INTEGER,
    fuzz_case_id INTEGER,
    browser_session_id INTEGER,
    browser_action_id INTEGER,
    capture_session_id INTEGER,
    request_body_id INTEGER REFERENCES bodies(id),
    response_body_id INTEGER REFERENCES bodies(id),
    request_body_hash TEXT,
    response_body_hash TEXT,
    error_message TEXT,
    PRIMARY KEY (project_id, exchange_id)
);

CREATE INDEX idx_exchanges_started ON exchanges(project_id, started_at DESC);
CREATE INDEX idx_exchanges_authority ON exchanges(project_id, authority, exchange_id DESC);
CREATE INDEX idx_exchanges_method ON exchanges(project_id, method, exchange_id DESC);
CREATE INDEX idx_exchanges_status ON exchanges(project_id, status_code, exchange_id DESC);
CREATE INDEX idx_exchanges_mime ON exchanges(project_id, mime, exchange_id DESC);
CREATE INDEX idx_exchanges_source ON exchanges(project_id, source, exchange_id DESC);
CREATE INDEX idx_exchanges_id_desc ON exchanges(project_id, exchange_id DESC);

CREATE TABLE message_headers (
    project_id INTEGER NOT NULL,
    exchange_id INTEGER NOT NULL,
    side TEXT NOT NULL,
    ordinal INTEGER NOT NULL,
    name TEXT NOT NULL,
    value BLOB NOT NULL,
    PRIMARY KEY (project_id, exchange_id, side, ordinal),
    FOREIGN KEY (project_id, exchange_id) REFERENCES exchanges(project_id, exchange_id) ON DELETE CASCADE
);

CREATE TABLE annotations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL,
    exchange_id INTEGER NOT NULL,
    display_title TEXT,
    note TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    revision INTEGER NOT NULL DEFAULT 1,
    FOREIGN KEY (project_id, exchange_id) REFERENCES exchanges(project_id, exchange_id) ON DELETE CASCADE
);

CREATE TABLE labels (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    UNIQUE(project_id, name)
);

CREATE TABLE exchange_labels (
    project_id INTEGER NOT NULL,
    exchange_id INTEGER NOT NULL,
    label_id INTEGER NOT NULL REFERENCES labels(id) ON DELETE CASCADE,
    PRIMARY KEY (project_id, exchange_id, label_id),
    FOREIGN KEY (project_id, exchange_id) REFERENCES exchanges(project_id, exchange_id) ON DELETE CASCADE
);

CREATE TABLE reply_workspaces (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name TEXT NOT NULL DEFAULT 'default',
    created_at TEXT NOT NULL
);

CREATE TABLE reply_tabs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    workspace_id INTEGER REFERENCES reply_workspaces(id) ON DELETE SET NULL,
    name TEXT NOT NULL,
    base_exchange_id INTEGER,
    revision INTEGER NOT NULL DEFAULT 1,
    protocol TEXT NOT NULL DEFAULT 'auto',
    draft_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE reply_revisions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tab_id INTEGER NOT NULL REFERENCES reply_tabs(id) ON DELETE CASCADE,
    revision INTEGER NOT NULL,
    draft_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE fuzz_jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    base_exchange_id INTEGER,
    state TEXT NOT NULL,
    strategy TEXT NOT NULL,
    template_json TEXT NOT NULL,
    estimated_cases INTEGER NOT NULL DEFAULT 0,
    completed_cases INTEGER NOT NULL DEFAULT 0,
    failed_cases INTEGER NOT NULL DEFAULT 0,
    limits_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE fuzz_cases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id INTEGER NOT NULL REFERENCES fuzz_jobs(id) ON DELETE CASCADE,
    case_index INTEGER NOT NULL,
    exchange_id INTEGER,
    status_code INTEGER,
    error TEXT,
    body_hash TEXT,
    payload_summary TEXT,
    UNIQUE(job_id, case_index)
);

CREATE TABLE browser_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    engine TEXT NOT NULL,
    engine_policy TEXT NOT NULL,
    current_url TEXT,
    state TEXT NOT NULL,
    fallback_used INTEGER NOT NULL DEFAULT 0,
    checkpoint_status TEXT,
    checkpoint_hash TEXT,
    checkpoint_version INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE browser_actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER NOT NULL REFERENCES browser_sessions(id) ON DELETE CASCADE,
    project_id INTEGER NOT NULL,
    action_type TEXT NOT NULL,
    status TEXT NOT NULL,
    error_code TEXT,
    created_at TEXT NOT NULL,
    finished_at TEXT
);

CREATE TABLE audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER,
    event_type TEXT NOT NULL,
    actor TEXT,
    target_type TEXT,
    target_id TEXT,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
);

CREATE TABLE project_seq (
    project_id INTEGER PRIMARY KEY REFERENCES projects(id) ON DELETE CASCADE,
    next_exchange_id INTEGER NOT NULL DEFAULT 1
);

CREATE VIRTUAL TABLE IF NOT EXISTS search_fts USING fts5(
    project_id UNINDEXED,
    exchange_id UNINDEXED,
    title,
    preview,
    labels,
    tokenize = 'porter'
);
