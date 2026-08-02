-- Keep the project's starting target as durable metadata. Existing projects
-- predate this field and therefore use an empty value until edited/imported.
ALTER TABLE projects ADD COLUMN target_url TEXT NOT NULL DEFAULT '';
