-- Grants and management holdings may bind an appointment of the employee member (security 04, D30): the appointment
-- is a source of theirs, indexed like the others; no record bound one before, so the index of the kind is complete.
ALTER TABLE authz_dependency DROP CONSTRAINT authz_dependency_kind_check;
ALTER TABLE authz_dependency ADD CONSTRAINT authz_dependency_kind_check
    CHECK (kind IN ('management_unit', 'role_revision', 'account', 'appointment'));
ALTER TABLE authz_dependency_index DROP CONSTRAINT authz_dependency_index_kind_check;
ALTER TABLE authz_dependency_index ADD CONSTRAINT authz_dependency_index_kind_check
    CHECK (kind IN ('management_unit', 'role_revision', 'account', 'appointment'));
INSERT INTO authz_dependency_index VALUES ('appointment', true);
