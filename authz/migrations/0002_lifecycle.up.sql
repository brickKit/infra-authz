-- Foundations item 3, T4a (security 08, "通用生命周期"): the full lifecycle of a security record. The state revision
-- advances with every state transition (a derived key carries it), apart from the content revision that only a
-- narrowing advances (the column revision). A record never comes back from ended: a re-grant is a new record that
-- names its predecessor.
ALTER TABLE authz_record DROP CONSTRAINT authz_record_state_check;
ALTER TABLE authz_record ADD CONSTRAINT authz_record_state_check
    CHECK (state IN ('requested', 'awaiting_confirmation', 'scheduled', 'active', 'held', 'ended'));
ALTER TABLE authz_record DROP CONSTRAINT authz_record_end_reason_check;
ALTER TABLE authz_record ADD CONSTRAINT authz_record_end_reason_check
    CHECK (end_reason IN ('expired', 'revoked', 'relinquished', 'source_ended', 'source_narrowed', 'superseded',
                          'rejected', 'cancelled', 'withdrawn'));
ALTER TABLE authz_record ADD COLUMN hold_reason text
    CHECK (hold_reason IN ('security_hold', 'uncomputable', 'restore_pending'));
ALTER TABLE authz_record ADD COLUMN state_revision bigint NOT NULL DEFAULT 1;
ALTER TABLE authz_record ADD COLUMN predecessor uuid REFERENCES authz_record;
ALTER TABLE authz_record ADD COLUMN effective_at timestamptz;          -- scheduled: when it is to take effect
ALTER TABLE authz_record ADD COLUMN review boolean NOT NULL DEFAULT false; -- partly outside its limits: to be reviewed
ALTER TABLE authz_record ADD COLUMN reason text;                         -- the reason of a rejection that ended it
ALTER TABLE authz_record ADD CONSTRAINT authz_record_held_reason CHECK ((state = 'held') = (hold_reason IS NOT NULL));
ALTER TABLE authz_record ADD CONSTRAINT authz_record_ended_reason CHECK ((state = 'ended') = (end_reason IS NOT NULL));
ALTER TABLE authz_record ADD CONSTRAINT authz_record_scheduled_at CHECK (state <> 'scheduled' OR effective_at IS NOT NULL);
CREATE INDEX authz_record_scheduled ON authz_record (effective_at) WHERE state = 'scheduled';
-- The record's own validity (09a's common valid): left-closed, right-open; past valid_until the record gives no access
-- at once, and the closure job ends it (expired) afterwards.
ALTER TABLE authz_record ADD COLUMN valid_from timestamptz;
ALTER TABLE authz_record ADD COLUMN valid_until timestamptz;
-- The last effective change request (09a's last_change): the requester and the key that bound it.
ALTER TABLE authz_record ADD COLUMN last_change text;
-- A change key's binding also names the record and the outcome it bound (09a's change_result).
ALTER TABLE authz_change ADD COLUMN record uuid;
