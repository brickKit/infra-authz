-- Foundations item 3, T6a (security 08's security dispositions, 09a's be.security.security_disposition, A128): a
-- disposition suspends a natural person's access within a scope of a governance domain; the person's effective
-- records in that scope are held (security_hold) and, while it is active, the person's segments that meet the
-- suspended scope are not given. Without the employee component a natural person is one platform principal.
CREATE TABLE authz_disposition (
    id                 uuid PRIMARY KEY,
    state              text NOT NULL CHECK (state IN ('active', 'released')),
    origin             text NOT NULL CHECK (origin IN ('admin', 'identity_side', 'admin_recovery')),
    subject            text NOT NULL,             -- the platform principal
    accounts           text[] NOT NULL,
    suspended_segments jsonb NOT NULL,            -- [] with all_scope: the person's every segment
    all_scope          boolean NOT NULL DEFAULT false,
    domain             uuid NOT NULL,             -- the governance unit
    disposer           text,
    confirmations      text[] NOT NULL DEFAULT '{}',
    signal_ref         text[] NOT NULL DEFAULT '{}',
    revision           bigint NOT NULL DEFAULT 1, -- the disposition revision: a release's confirmation binds it
    released_by        text,
    change             text,                      -- the change that made it
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX authz_disposition_subject ON authz_disposition (subject) WHERE state = 'active';
-- the disposition a held record is held by
ALTER TABLE authz_record ADD COLUMN disposition uuid REFERENCES authz_disposition;
