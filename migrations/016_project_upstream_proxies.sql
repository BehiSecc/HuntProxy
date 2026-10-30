CREATE TABLE project_upstream_proxies (
    project_id INTEGER PRIMARY KEY REFERENCES projects(id) ON DELETE CASCADE,
    -- A present row with NULL proxy explicitly routes directly.
    proxy TEXT
);
