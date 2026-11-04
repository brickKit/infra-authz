-- Foundations item 3, T4g (security 08, "影响闭包"): the dependency index, so the closure job finds the records a
-- source's change affects. Each record's sources follow from its content, written with the record; a source kind
-- whose index is not complete is not trusted (the job then scans and marks the whole source domain for review).
CREATE TABLE authz_dependency (
    record uuid NOT NULL REFERENCES authz_record,
    kind   text NOT NULL CHECK (kind IN ('management_unit', 'role_revision', 'account')),
    ref    text NOT NULL,
    role   text NOT NULL CHECK (role IN ('ceiling', 'eligibility', 'permission_basis')),
    PRIMARY KEY (record, kind, ref)
);
CREATE INDEX authz_dependency_source ON authz_dependency (kind, ref);
INSERT INTO authz_dependency
    SELECT id, 'management_unit', body->>'governance_unit', 'ceiling' FROM authz_record
        WHERE record_type = 'grant' AND coalesce(body->>'governance_unit', '') <> ''
    UNION ALL SELECT id, 'role_revision', body->>'role_revision', 'permission_basis' FROM authz_record
        WHERE record_type = 'grant' AND coalesce(body->>'role_revision', '') <> ''
    UNION ALL SELECT id, 'account', body->>'grantee', 'eligibility' FROM authz_record
        WHERE record_type = 'grant' AND coalesce(body->>'grantee', '') <> ''
    UNION ALL SELECT id, 'management_unit', body->>'parent', 'ceiling' FROM authz_record
        WHERE record_type = 'management_unit' AND coalesce(body->>'parent', '') <> ''
    UNION ALL SELECT id, 'management_unit', body->>'unit', 'ceiling' FROM authz_record
        WHERE record_type = 'management_holding' AND coalesce(body->>'unit', '') <> ''
    UNION ALL SELECT id, 'account', body->>'holder', 'eligibility' FROM authz_record
        WHERE record_type = 'management_holding' AND coalesce(body->>'holder', '') <> '';
CREATE TABLE authz_dependency_index (
    kind     text PRIMARY KEY CHECK (kind IN ('management_unit', 'role_revision', 'account')),
    complete boolean NOT NULL
);
INSERT INTO authz_dependency_index VALUES ('management_unit', true), ('role_revision', true), ('account', true);
-- A source domain the closure job could not trust its index for: to be reviewed (security 08).
CREATE TABLE authz_review_domain (
    kind      text NOT NULL,
    ref       text NOT NULL,
    marked_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (kind, ref)
);
