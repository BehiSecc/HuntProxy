-- Headers repeat heavily (the same cookies, user agents and policies on every
-- exchange), so each distinct name and value is stored once and a message's
-- header rows keep only their ids. message_headers becomes a view with the old
-- columns, so readers and SQL copies see the same rows as before.
--
-- The id tables have no foreign keys: SQLite would scan every header row for
-- each deleted name or value. Rows that nothing references any more are
-- removed where exchanges are deleted.

-- The copy below looks up every row's name and value; a larger page cache
-- keeps those lookups in memory. The default is restored at the end.
PRAGMA cache_size = -262144;

CREATE TABLE header_names (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE
);

CREATE TABLE header_values (
    id INTEGER PRIMARY KEY,
    value BLOB NOT NULL UNIQUE
);

-- side: 0 request, 1 response.
CREATE TABLE message_header_rows (
    project_id INTEGER NOT NULL,
    exchange_id INTEGER NOT NULL,
    side INTEGER NOT NULL CHECK (side IN (0, 1)),
    ordinal INTEGER NOT NULL,
    name_id INTEGER NOT NULL,
    value_id INTEGER NOT NULL,
    PRIMARY KEY (project_id, exchange_id, side, ordinal),
    FOREIGN KEY (project_id, exchange_id) REFERENCES exchanges(project_id, exchange_id) ON DELETE CASCADE
) WITHOUT ROWID;

-- OR IGNORE interns each value in one pass over the unique index; DISTINCT
-- first built a temporary copy of every distinct value. Nothing else writes
-- these tables yet, so the conflict clause cannot replace a row.
INSERT OR IGNORE INTO header_names (name) SELECT name FROM message_headers;
INSERT OR IGNORE INTO header_values (value) SELECT value FROM message_headers;

-- A side other than request or response maps to NULL and fails the copy.
INSERT INTO message_header_rows (project_id, exchange_id, side, ordinal, name_id, value_id)
SELECT h.project_id, h.exchange_id,
       CASE h.side WHEN 'request' THEN 0 WHEN 'response' THEN 1 END,
       h.ordinal, n.id, v.id
  FROM message_headers h
  JOIN header_names n ON n.name = h.name
  JOIN header_values v ON v.value = h.value;

-- Every row was copied, or the migration fails before the old table is dropped.
CREATE TEMP TABLE migration_018_check (copied INTEGER NOT NULL CHECK (copied = 1));
INSERT INTO migration_018_check
SELECT (SELECT COUNT(*) FROM message_headers) = (SELECT COUNT(*) FROM message_header_rows);
DROP TABLE migration_018_check;

DROP TABLE message_headers;

CREATE VIEW message_headers (project_id, exchange_id, side, ordinal, name, value) AS
SELECT r.project_id, r.exchange_id,
       CASE r.side WHEN 0 THEN 'request' ELSE 'response' END,
       r.ordinal, n.name, v.value
  FROM message_header_rows r
  JOIN header_names n ON n.id = r.name_id
  JOIN header_values v ON v.id = r.value_id;

-- Writes through the view intern the name and value. NOT EXISTS instead of
-- OR IGNORE: an outer INSERT OR REPLACE would otherwise replace a shared row
-- and change its id under every header that uses it.
CREATE TRIGGER message_headers_insert INSTEAD OF INSERT ON message_headers
BEGIN
    INSERT INTO header_names (name)
        SELECT NEW.name WHERE NOT EXISTS (SELECT 1 FROM header_names WHERE name = NEW.name);
    INSERT INTO header_values (value)
        SELECT NEW.value WHERE NOT EXISTS (SELECT 1 FROM header_values WHERE value = NEW.value);
    INSERT INTO message_header_rows (project_id, exchange_id, side, ordinal, name_id, value_id)
    VALUES (
        NEW.project_id,
        NEW.exchange_id,
        CASE NEW.side WHEN 'request' THEN 0 WHEN 'response' THEN 1 END,
        NEW.ordinal,
        (SELECT id FROM header_names WHERE name = NEW.name),
        (SELECT id FROM header_values WHERE value = NEW.value)
    );
END;

CREATE TRIGGER message_headers_delete INSTEAD OF DELETE ON message_headers
BEGIN
    DELETE FROM message_header_rows
     WHERE project_id = OLD.project_id
       AND exchange_id = OLD.exchange_id
       AND side = CASE OLD.side WHEN 'request' THEN 0 ELSE 1 END
       AND ordinal = OLD.ordinal;
END;

-- Bodies captured through a spool were stored uncompressed. A background pass
-- compresses them once, resuming from cursor (the last body id it handled).
CREATE TABLE storage_maintenance (
    task TEXT PRIMARY KEY,
    cursor INTEGER NOT NULL DEFAULT 0,
    finished_at TEXT
);
INSERT INTO storage_maintenance (task) VALUES ('compress_raw_bodies');

PRAGMA cache_size = -2000;
