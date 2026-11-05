-- Foundations item 3, T9d (security 08, "管理员账号的状态变更"): a confirmation of an account's status change binds
-- the account, the status and the security version the change is made on; the account status that carries it uses it.
ALTER TABLE authz_confirmation ADD COLUMN account text;
ALTER TABLE authz_confirmation ADD COLUMN target_state text CHECK (target_state IN ('active', 'disabled', 'security_frozen'));
ALTER TABLE authz_confirmation ADD COLUMN target_state_version bigint;
ALTER TABLE authz_confirmation DROP CONSTRAINT authz_confirmation_binding;
ALTER TABLE authz_confirmation ADD CONSTRAINT authz_confirmation_binding CHECK (
    target IS NOT NULL AND disposition IS NULL AND plan IS NULL AND account IS NULL
        AND (candidate_digest IS NULL) <> (expected_revision IS NULL)
    OR target IS NULL AND disposition IS NOT NULL AND disposition_revision IS NOT NULL AND plan IS NULL AND account IS NULL
        AND candidate_digest IS NULL AND expected_revision IS NULL
    OR target IS NULL AND disposition IS NULL AND plan IS NOT NULL AND plan_digest IS NOT NULL AND account IS NULL
        AND candidate_digest IS NULL AND expected_revision IS NULL
    OR target IS NULL AND disposition IS NULL AND plan IS NULL AND account IS NOT NULL AND target_state IS NOT NULL
        AND target_state_version IS NOT NULL AND candidate_digest IS NULL AND expected_revision IS NULL);
CREATE INDEX authz_confirmation_account ON authz_confirmation (account) WHERE account IS NOT NULL;

-- The status each account had when last applied: a change of it is a transition (re-enabled, disabled, ...).
CREATE TABLE authz_account_seen (
    principal text PRIMARY KEY,
    status    text NOT NULL,
    version   bigint NOT NULL
);
