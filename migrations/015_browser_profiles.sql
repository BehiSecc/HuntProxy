-- Named persistent Chromium identities per project.
ALTER TABLE browser_sessions ADD COLUMN profile_name TEXT;

-- Historical sessions may have been ephemeral or persistent. Leave their
-- profile unknown rather than inventing identity provenance; the legacy
-- project-level state.json remains the persistent "default" profile state.
