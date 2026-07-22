-- Offline activation request/response records. The plaintext activation code is
-- NEVER stored; only the resolved license/device and the issued response token.
-- request_id is client-generated and unique, giving idempotency + replay
-- protection (re-submitting the same request returns the same response).

BEGIN;

CREATE TABLE offline_requests (
  request_id    TEXT PRIMARY KEY,
  license_id    TEXT NOT NULL REFERENCES licenses(id),
  device_id     TEXT NOT NULL,
  created_at    BIGINT NOT NULL,
  processed_at  BIGINT NOT NULL
);
CREATE INDEX idx_offline_requests_license ON offline_requests(license_id);

CREATE TABLE offline_responses (
  request_id    TEXT PRIMARY KEY REFERENCES offline_requests(request_id),
  license_id    TEXT NOT NULL REFERENCES licenses(id),
  device_id     TEXT NOT NULL,
  token         TEXT NOT NULL,
  issued_at     BIGINT NOT NULL
);

COMMIT;
