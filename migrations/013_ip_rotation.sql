CREATE TABLE ip_rotation_profiles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    target_origin TEXT NOT NULL,
    stage_name TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(project_id, target_origin)
);

CREATE INDEX idx_ip_rotation_profiles_project_enabled
    ON ip_rotation_profiles(project_id, enabled, target_origin);

CREATE TABLE ip_rotation_gateways (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    profile_id INTEGER NOT NULL REFERENCES ip_rotation_profiles(id) ON DELETE CASCADE,
    region TEXT NOT NULL,
    rest_api_id TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    UNIQUE(profile_id, region),
    UNIQUE(region, rest_api_id)
);

CREATE INDEX idx_ip_rotation_gateways_profile
    ON ip_rotation_gateways(profile_id, id);
