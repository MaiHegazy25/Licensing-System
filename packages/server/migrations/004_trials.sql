-- Trial licenses: per-product trial policy + one-trial-per-device registry.
--
-- The UNIQUE (product_id, device_id) constraint is the atomic guard that makes
-- "one trial per device per product" race-proof: concurrent requests can create
-- at most one trials row. The guard is keyed on the client-derived device id,
-- which raises the cost of trial farming but cannot fully prevent it (honest
-- limitation, see threat model).

BEGIN;

ALTER TABLE products ADD COLUMN trial_enabled  BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE products ADD COLUMN trial_days     INTEGER NOT NULL DEFAULT 14;
ALTER TABLE products ADD COLUMN trial_edition  TEXT    NOT NULL DEFAULT 'trial';
ALTER TABLE products ADD COLUMN trial_features JSONB   NOT NULL DEFAULT '[]'::jsonb;

-- Trial activations are issued without an activation code.
ALTER TABLE activations ALTER COLUMN activation_code_id DROP NOT NULL;

CREATE TABLE trials (
  id          TEXT PRIMARY KEY,
  product_id  TEXT NOT NULL REFERENCES products(id),
  license_id  TEXT NOT NULL REFERENCES licenses(id),
  device_id   TEXT NOT NULL,
  created_at  BIGINT NOT NULL,
  UNIQUE (product_id, device_id)
);
CREATE INDEX idx_trials_license ON trials(license_id);

COMMIT;
