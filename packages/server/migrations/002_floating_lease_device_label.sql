-- Floating leases: add an optional human-readable device label (parallels
-- activations.device_label). Append-only migration; 001 stays immutable.

BEGIN;

ALTER TABLE floating_leases ADD COLUMN device_label TEXT;

-- Support "active leases for a license" counting/listing: released and unexpired.
CREATE INDEX IF NOT EXISTS idx_floating_active_expiry
  ON floating_leases (license_id, expires_at)
  WHERE released_at IS NULL;

COMMIT;
