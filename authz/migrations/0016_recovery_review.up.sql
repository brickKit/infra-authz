-- Foundations item 4, T9c (assembly protocol 15, 6.5; A142): a full recovery's invariant check closes the subjects
-- under review with a disposition of its own origin, released by the people of step 10 like any other.
ALTER TABLE authz_disposition DROP CONSTRAINT authz_disposition_origin_check;
ALTER TABLE authz_disposition ADD CONSTRAINT authz_disposition_origin_check
    CHECK (origin IN ('admin', 'identity_side', 'admin_recovery', 'recovery_review'));
