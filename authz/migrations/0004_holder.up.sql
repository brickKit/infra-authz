-- D82: the member's own resource has a principal dimension, holder (a grant's grantee, a holding's holder), so a
-- principal sees and relinquishes its own records only; the column the list authorization compiles to.
ALTER TABLE authz_record ADD COLUMN holder text GENERATED ALWAYS AS (coalesce(body->>'grantee', body->>'holder')) STORED;
