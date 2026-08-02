CREATE TABLE websocket_connections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    handshake_exchange_id INTEGER,
    url TEXT NOT NULL,
    protocol TEXT,
    state TEXT NOT NULL DEFAULT 'open',
    opened_at TEXT NOT NULL,
    closed_at TEXT,
    message_count INTEGER NOT NULL DEFAULT 0,
    client_bytes INTEGER NOT NULL DEFAULT 0,
    server_bytes INTEGER NOT NULL DEFAULT 0,
    last_error TEXT
);

CREATE INDEX idx_websocket_connections_project
ON websocket_connections(project_id, id DESC);

CREATE TABLE websocket_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    connection_id INTEGER NOT NULL REFERENCES websocket_connections(id) ON DELETE CASCADE,
    direction TEXT NOT NULL,
    opcode TEXT NOT NULL,
    payload BLOB NOT NULL,
    payload_length INTEGER NOT NULL,
    truncated INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);

CREATE INDEX idx_websocket_messages_connection
ON websocket_messages(project_id, connection_id, id);
