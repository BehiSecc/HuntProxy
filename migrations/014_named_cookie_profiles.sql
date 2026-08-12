-- Independently selectable cookie identities for identity-aware extensions.
-- Unlike project_cookies, these profiles are never applied automatically.

CREATE TABLE named_cookie_profiles (
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    target_url TEXT NOT NULL,
    cookie_header TEXT NOT NULL,
    names_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (project_id, name)
);
