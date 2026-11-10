-- A confirmation of an account's link to an employee or its end (security 08 row 21): the employee, the account
-- (the account column), the action and the employee's version it is made on.
ALTER TABLE authz_confirmation ADD COLUMN employee text;
ALTER TABLE authz_confirmation ADD COLUMN link_action text CHECK (link_action IN ('link', 'unlink'));
ALTER TABLE authz_confirmation ADD COLUMN employee_version bigint;
ALTER TABLE authz_confirmation DROP CONSTRAINT authz_confirmation_binding;
ALTER TABLE authz_confirmation ADD CONSTRAINT authz_confirmation_binding CHECK (
    target IS NOT NULL AND disposition IS NULL AND plan IS NULL AND account IS NULL AND employee IS NULL
        AND (candidate_digest IS NULL) <> (expected_revision IS NULL)
    OR target IS NULL AND disposition IS NOT NULL AND disposition_revision IS NOT NULL AND plan IS NULL AND account IS NULL
        AND employee IS NULL AND candidate_digest IS NULL AND expected_revision IS NULL
    OR target IS NULL AND disposition IS NULL AND plan IS NOT NULL AND plan_digest IS NOT NULL AND account IS NULL
        AND employee IS NULL AND candidate_digest IS NULL AND expected_revision IS NULL
    OR target IS NULL AND disposition IS NULL AND plan IS NULL AND account IS NOT NULL AND target_state IS NOT NULL
        AND target_state_version IS NOT NULL AND employee IS NULL AND candidate_digest IS NULL AND expected_revision IS NULL
    OR target IS NULL AND disposition IS NULL AND plan IS NULL AND account IS NOT NULL AND target_state IS NULL
        AND employee IS NOT NULL AND link_action IS NOT NULL AND employee_version IS NOT NULL
        AND candidate_digest IS NULL AND expected_revision IS NULL);
