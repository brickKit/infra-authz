-- Foundations item 3, T7d (security 08's batch plans, 09a's change_plan, A132): a plan and its items. An item is a
-- change request without a key of its own; each run of it enters the effect point under the member's derived key
-- plan:<plan>:<item>:<attempt>. A plan above the confirmation threshold is confirmed by a second person, bound to the
-- plan and its preview digest (or, for an item reviewed again, the item's digest).
CREATE TABLE authz_plan (
    id               uuid PRIMARY KEY,
    initiator        text NOT NULL,
    plan_key         text NOT NULL,
    draft_digest     text NOT NULL, -- the items as submitted: the same key again with other items conflicts
    plan_state       text NOT NULL CHECK (plan_state IN ('draft', 'previewed', 'confirmed', 'executing', 'completed',
                                                         'partially_completed', 'cancelled', 'expired')),
    preview_digest   text,
    previewed_at     timestamptz,
    expires_at       timestamptz,
    comparisons      bigint,
    confirmed_at     timestamptz,
    second_confirmer text, -- the confirmer a plan above the threshold took
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now(),
    UNIQUE (initiator, plan_key)
);

CREATE TABLE authz_plan_item (
    plan       uuid NOT NULL REFERENCES authz_plan,
    item_key   text NOT NULL,
    position   int NOT NULL,
    request    jsonb NOT NULL, -- 09a's change_request without its key; the target's revisions as previewed
    item_state text NOT NULL CHECK (item_state IN ('pending', 'applied', 'rejected', 'needs_review')),
    attempt    int NOT NULL DEFAULT 1,
    record     uuid, -- the record a run made or saved
    result     jsonb, -- the last run's change_result
    reason     text, -- why it ended without a run: plan_terminated, not_reviewed
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (plan, item_key),
    UNIQUE (plan, position)
);
CREATE INDEX authz_plan_item_record ON authz_plan_item (record) WHERE record IS NOT NULL;

ALTER TABLE authz_confirmation ADD COLUMN plan uuid REFERENCES authz_plan;
ALTER TABLE authz_confirmation ADD COLUMN plan_digest text;
ALTER TABLE authz_confirmation DROP CONSTRAINT authz_confirmation_binding;
ALTER TABLE authz_confirmation ADD CONSTRAINT authz_confirmation_binding CHECK (
    target IS NOT NULL AND disposition IS NULL AND plan IS NULL AND (candidate_digest IS NULL) <> (expected_revision IS NULL)
    OR target IS NULL AND disposition IS NOT NULL AND disposition_revision IS NOT NULL AND plan IS NULL
        AND candidate_digest IS NULL AND expected_revision IS NULL
    OR target IS NULL AND disposition IS NULL AND plan IS NOT NULL AND plan_digest IS NOT NULL
        AND candidate_digest IS NULL AND expected_revision IS NULL);
