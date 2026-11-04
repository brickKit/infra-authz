-- Foundations item 3, T6b (security 08's release of a disposition, 09a's be.security.confirmation): a release of a
-- disposition of an authorization admin is confirmed bound to the disposition and its revision, not to a record.
ALTER TABLE authz_confirmation ALTER COLUMN target DROP NOT NULL;
ALTER TABLE authz_confirmation ADD COLUMN disposition uuid REFERENCES authz_disposition;
ALTER TABLE authz_confirmation ADD COLUMN disposition_revision bigint;
ALTER TABLE authz_confirmation DROP CONSTRAINT authz_confirmation_check;
ALTER TABLE authz_confirmation ADD CONSTRAINT authz_confirmation_binding CHECK (
    target IS NOT NULL AND disposition IS NULL AND (candidate_digest IS NULL) <> (expected_revision IS NULL)
    OR target IS NULL AND disposition IS NOT NULL AND disposition_revision IS NOT NULL
        AND candidate_digest IS NULL AND expected_revision IS NULL);
