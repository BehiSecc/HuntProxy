-- Named persistent Chromium identities per project.
ALTER TABLE browser_sessions ADD COLUMN profile_name TEXT;

-- Existing persistent browser history belongs to the legacy default profile.
UPDATE browser_sessions SET profile_name='default' WHERE profile_name IS NULL;
