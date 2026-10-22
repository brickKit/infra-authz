-- The authorization member's data (security 08, 09a): accepted definitions, security records and their changes, the
-- security revision, and the member's own state. The records are the authority; views are computed from them.

-- One row: the deployment recovery generation and this member's instance (security 03, protocol 14 rule 3).
CREATE TABLE authz_state (
    single              boolean PRIMARY KEY DEFAULT true CHECK (single),
    recovery_generation bigint NOT NULL DEFAULT 1,
    instance            text NOT NULL,                  -- generated at installation, never changes
    security_revision   bigint NOT NULL DEFAULT 1       -- domain authz.security.deployment: advanced by every effective change
);

-- Accepted definitions (DefinitionService.Submit), by digest; the canonical bytes as received.
CREATE TABLE authz_definition (
    digest      text PRIMARY KEY,
    component   text NOT NULL,
    record_type text NOT NULL CHECK (record_type IN ('be.security.resource_definition', 'be.security.operation_definition')),
    key         text NOT NULL,
    record      bytea NOT NULL
);
CREATE TABLE authz_definition_set (
    component   text NOT NULL,
    version     text NOT NULL,
    set_digest  text NOT NULL,
    digests     text[] NOT NULL,
    accepted_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (component, version)
);
-- The version whose definitions views use, per component: the last one accepted.
CREATE TABLE authz_component (
    component   text PRIMARY KEY,
    version     text NOT NULL,
    accepted_at timestamptz NOT NULL DEFAULT now()
);

-- Security records (security 08): management units, management holdings, role revisions, grants. The record
-- specific fields are in body (09a's field tables); state is the subset of the lifecycle this step uses.
CREATE TABLE authz_record (
    id           uuid PRIMARY KEY,
    record_type  text NOT NULL CHECK (record_type IN ('management_unit', 'management_holding', 'role_revision', 'grant')),
    state        text NOT NULL CHECK (state IN ('active', 'ended')),
    end_reason   text CHECK (end_reason IN ('revoked', 'relinquished', 'superseded')),
    revision     bigint NOT NULL DEFAULT 1,
    body         jsonb NOT NULL,
    requested_by text NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX authz_record_active ON authz_record (record_type) WHERE state = 'active';

-- Change keys (security 08, "变更键"): a bound key returns its result again; other content under it is a conflict.
CREATE TABLE authz_change (
    requested_by   text NOT NULL,
    change_key     text NOT NULL,
    content_digest text NOT NULL,
    result         jsonb NOT NULL,
    created_at     timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (requested_by, change_key)
);
