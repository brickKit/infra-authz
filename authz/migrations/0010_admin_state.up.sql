-- Foundations item 3, T6e (security 08's pending recovery; 09a's be.security.deployment_admin_state): the
-- deployment's authorization state. Provably no available authorization admin: recovery pending, left only through
-- an administrator recovery.
ALTER TABLE authz_state ADD COLUMN admin_state text NOT NULL DEFAULT 'operational'
    CHECK (admin_state IN ('operational', 'recovery_pending', 'admin_recovery'));
ALTER TABLE authz_state ADD COLUMN admin_state_since timestamptz NOT NULL DEFAULT now();
ALTER TABLE authz_state ADD COLUMN unavailable_holdings jsonb NOT NULL DEFAULT '[]';
ALTER TABLE authz_state ADD COLUMN entered_from text;
