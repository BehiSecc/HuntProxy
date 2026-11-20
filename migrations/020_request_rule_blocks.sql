-- A URL request rule with operation 'block' answers a matching proxied request
-- itself instead of sending it upstream. method limits the rule to one HTTP
-- method (NULL matches any), and the response_* columns describe the synthetic
-- response. All four columns are NULL for every other operation.
ALTER TABLE request_rules ADD COLUMN method TEXT;
ALTER TABLE request_rules ADD COLUMN response_status INTEGER;
ALTER TABLE request_rules ADD COLUMN response_content_type TEXT;
ALTER TABLE request_rules ADD COLUMN response_body TEXT;
