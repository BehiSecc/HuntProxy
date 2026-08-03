-- Browser support is Chromium-only. Preserve session history and portable
-- checkpoints while normalizing metadata created by older Lightpanda builds.
UPDATE browser_sessions
SET engine = 'chromium',
    engine_policy = 'chromium',
    fallback_used = 0,
    state = CASE WHEN state = 'migrating' THEN 'interrupted' ELSE state END,
    checkpoint_status = CASE
        WHEN checkpoint_status = 'fallback_chromium' THEN 'ok'
        ELSE checkpoint_status
    END
WHERE engine = 'lightpanda'
   OR engine_policy = 'auto'
   OR fallback_used != 0
   OR state = 'migrating'
   OR checkpoint_status = 'fallback_chromium';
