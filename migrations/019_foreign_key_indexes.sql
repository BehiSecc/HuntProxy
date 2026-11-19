-- When a row that foreign keys point at is deleted, SQLite looks for the rows
-- that reference it. With no index on the referencing columns that is a scan
-- of the whole referencing table for every deleted row.
--
-- exchanges.request_body_id and response_body_id reference bodies(id), so each
-- body removed with a project or with cleared History scanned every exchange
-- twice. Deleting a 4,800-exchange project from a database of 24,000 exchanges
-- held the write lock for over a minute, and captures in every other project
-- failed while they waited for it.
--
-- Most requests have no body, so these two indexes leave NULLs out. The
-- foreign-key check is an equality on the column and can still use them.
CREATE INDEX IF NOT EXISTS idx_exchanges_request_body
    ON exchanges(request_body_id) WHERE request_body_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_exchanges_response_body
    ON exchanges(response_body_id) WHERE response_body_id IS NOT NULL;

-- The same scan ran for every WebSocket connection, browser session, Reply tab
-- and label that a deleted project owned.
CREATE INDEX IF NOT EXISTS idx_websocket_messages_connection_id
    ON websocket_messages(connection_id);
CREATE INDEX IF NOT EXISTS idx_browser_actions_session
    ON browser_actions(session_id);
CREATE INDEX IF NOT EXISTS idx_reply_revisions_tab
    ON reply_revisions(tab_id);
CREATE INDEX IF NOT EXISTS idx_exchange_labels_label
    ON exchange_labels(label_id);
