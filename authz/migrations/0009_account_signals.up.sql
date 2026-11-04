-- Foundations item 3, T6c (security 08's identity-side dispositions): what this member last derived from each
-- account's status, so that a disposition follows a transition (to frozen, or disabled with a compromised or
-- suspicious mark), not the arrival of a signal; an account seen the first time is no transition.
CREATE TABLE authz_account_signal (
    principal  text PRIMARY KEY,
    marked     boolean NOT NULL, -- frozen, or disabled with a security mark
    ref        text NOT NULL,    -- the last status record applied: <account>@<its revision>
    updated_at timestamptz NOT NULL DEFAULT now()
);
