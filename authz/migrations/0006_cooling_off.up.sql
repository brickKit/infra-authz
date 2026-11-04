-- Foundations item 3, T5 (security 08's protected operations): a protected widening the deployment owner confirmed while
-- another authorization admin had become unavailable within the cooling-off waits until it ends; until then any
-- available authorization admin but its applicant may cancel it (a veto, row 7).
ALTER TABLE authz_record ADD COLUMN cooling_off_until timestamptz;
