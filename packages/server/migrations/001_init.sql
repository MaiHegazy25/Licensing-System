-- Vehiclevo Licensing — initial schema (production path).
-- Covers the vertical-slice entities plus the surrounding model from the brief.
-- Concurrency: floating-seat enforcement (later phase) uses row locks /
-- conditional UPDATEs against `licenses.maximum_seats`; the version columns give
-- optimistic concurrency for admin edits.

BEGIN;

CREATE TABLE customers (
  id            TEXT PRIMARY KEY,
  name          TEXT NOT NULL,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE organizations (
  id            TEXT PRIMARY KEY,
  customer_id   TEXT NOT NULL REFERENCES customers(id),
  name          TEXT NOT NULL,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE products (
  id            TEXT PRIMARY KEY,
  key           TEXT NOT NULL UNIQUE,
  name          TEXT NOT NULL,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE product_versions (
  id            TEXT PRIMARY KEY,
  product_id    TEXT NOT NULL REFERENCES products(id),
  semver        TEXT NOT NULL,
  UNIQUE (product_id, semver)
);

CREATE TABLE editions (
  id            TEXT PRIMARY KEY,
  product_id    TEXT NOT NULL REFERENCES products(id),
  code          TEXT NOT NULL,
  UNIQUE (product_id, code)
);

CREATE TABLE features (
  id            TEXT PRIMARY KEY,
  product_id    TEXT NOT NULL REFERENCES products(id),
  code          TEXT NOT NULL,
  UNIQUE (product_id, code)
);

-- Which features an edition grants.
CREATE TABLE edition_features (
  edition_id    TEXT NOT NULL REFERENCES editions(id),
  feature_id    TEXT NOT NULL REFERENCES features(id),
  PRIMARY KEY (edition_id, feature_id)
);

CREATE TABLE licenses (
  id                     TEXT PRIMARY KEY,
  customer_id            TEXT NOT NULL REFERENCES customers(id),
  organization_id        TEXT REFERENCES organizations(id),
  product_id             TEXT NOT NULL REFERENCES products(id),
  edition                TEXT NOT NULL,
  enabled_features       JSONB NOT NULL DEFAULT '[]'::jsonb,
  license_type           TEXT NOT NULL
                           CHECK (license_type IN
                             ('named_user','device','floating','subscription','perpetual','trial')),
  status                 TEXT NOT NULL DEFAULT 'active'
                           CHECK (status IN ('draft','active','suspended','expired','revoked')),
  maximum_seats          INTEGER NOT NULL CHECK (maximum_seats >= 1),
  not_before             BIGINT NOT NULL,
  expires_at             BIGINT,               -- NULL = perpetual
  maintenance_expires_at BIGINT,
  grace_period_seconds   INTEGER NOT NULL DEFAULT 0,
  offline_until          BIGINT,
  created_at             BIGINT NOT NULL,
  updated_at             BIGINT NOT NULL,
  version                INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX idx_licenses_customer ON licenses(customer_id);
CREATE INDEX idx_licenses_status ON licenses(status);

-- Only the HASH of an activation code is stored, never the plaintext.
CREATE TABLE activation_codes (
  id                TEXT PRIMARY KEY,
  license_id        TEXT NOT NULL REFERENCES licenses(id),
  code_hash         TEXT NOT NULL UNIQUE,
  status            TEXT NOT NULL DEFAULT 'unused'
                      CHECK (status IN ('unused','consumed','revoked')),
  max_activations   INTEGER NOT NULL DEFAULT 1,
  used_activations  INTEGER NOT NULL DEFAULT 0,
  created_at        BIGINT NOT NULL,
  consumed_at       BIGINT
);
CREATE INDEX idx_activation_codes_license ON activation_codes(license_id);

-- A device that consumed a code. device_id is a SALTED DERIVED id, never a raw MAC.
CREATE TABLE activations (
  id                  TEXT PRIMARY KEY,
  license_id          TEXT NOT NULL REFERENCES licenses(id),
  activation_code_id  TEXT NOT NULL REFERENCES activation_codes(id),
  device_id           TEXT NOT NULL,
  device_label        TEXT,
  status              TEXT NOT NULL DEFAULT 'active'
                        CHECK (status IN ('active','deactivated')),
  activated_at        BIGINT NOT NULL,
  last_seen_at        BIGINT NOT NULL,
  deactivated_at      BIGINT
);
-- At most one ACTIVE activation per (license, device).
CREATE UNIQUE INDEX uq_activation_active_device
  ON activations(license_id, device_id) WHERE status = 'active';
CREATE INDEX idx_activations_license ON activations(license_id);

-- Floating/concurrent seat leases (later phase). Row-level locking enforces cap.
CREATE TABLE floating_leases (
  id            TEXT PRIMARY KEY,
  license_id    TEXT NOT NULL REFERENCES licenses(id),
  device_id     TEXT NOT NULL,
  acquired_at   BIGINT NOT NULL,
  expires_at    BIGINT NOT NULL,           -- heartbeat extends this
  released_at   BIGINT
);
CREATE INDEX idx_floating_active ON floating_leases(license_id) WHERE released_at IS NULL;

CREATE TABLE revocations (
  license_id    TEXT PRIMARY KEY REFERENCES licenses(id),
  reason        TEXT NOT NULL,
  revoked_at    BIGINT NOT NULL
);

-- Signing key METADATA only (never private key material).
CREATE TABLE signing_keys (
  kid            TEXT PRIMARY KEY,
  algorithm      TEXT NOT NULL DEFAULT 'EdDSA',
  public_key_pem TEXT NOT NULL,
  state          TEXT NOT NULL DEFAULT 'active'
                   CHECK (state IN ('active','retiring','retired')),
  created_at     BIGINT NOT NULL,
  retired_at     BIGINT
);

-- Append-only audit + security event logs.
CREATE TABLE audit_events (
  id          TEXT PRIMARY KEY,
  type        TEXT NOT NULL,
  license_id  TEXT REFERENCES licenses(id),
  actor       TEXT NOT NULL,
  at          BIGINT NOT NULL,
  metadata    JSONB NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX idx_audit_license ON audit_events(license_id);
CREATE INDEX idx_audit_at ON audit_events(at);

CREATE TABLE security_events (
  id          TEXT PRIMARY KEY,
  type        TEXT NOT NULL,   -- e.g. rate_limit_hit, bad_signature, replay_detected
  subject     TEXT,            -- device id / ip hash / actor
  at          BIGINT NOT NULL,
  metadata    JSONB NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX idx_security_at ON security_events(at);

COMMIT;
