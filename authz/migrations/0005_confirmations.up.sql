-- Foundations item 3, T5a (security 08's confirmation records, 09a's be.security.confirmation): a confirmation binds
-- its object: a saved widening's candidate digest, or a tightening's target at a content revision. Used once: the
-- change that applied with it is recorded.
CREATE TABLE authz_confirmation (
    id                 uuid PRIMARY KEY,
    target             uuid NOT NULL REFERENCES authz_record,
    candidate_digest   text,   -- a saved widening (awaiting confirmation): the candidate it confirms
    expected_revision  bigint, -- a tightening: the target's content revision it confirms
    confirmer          text NOT NULL,
    basis              text NOT NULL CHECK (basis IN ('holding', 'deployment_owner')),
    confirmed_at       timestamptz NOT NULL DEFAULT now(),
    expires_at         timestamptz NOT NULL,
    waiting_since      timestamptz,
    consumed_by_change text,
    CHECK ((candidate_digest IS NULL) <> (expected_revision IS NULL))
);
CREATE INDEX authz_confirmation_target ON authz_confirmation (target);
-- A saved widening keeps the digest its candidate was submitted with, for its confirmations to bind.
ALTER TABLE authz_record ADD COLUMN candidate_digest text;
