-- Foundations item 3, T6f (security 08's administrator recovery, A129): each signed recovery request is used once;
-- the identity a recovery restores is what brings the deployment back to operational.
CREATE TABLE authz_recovery_nonce (
    nonce      text PRIMARY KEY,
    action     text NOT NULL,
    used_at    timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE authz_state ADD COLUMN recovery_identity text;
