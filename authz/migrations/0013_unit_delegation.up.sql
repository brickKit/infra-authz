-- Foundations item 3, T7b (09a's management_unit, A131): a unit lists its management_actions and its
-- max_subdelegation_depth. Units made before this version have neither: they get every action and a depth of the
-- deployment's default maximum (6) less their level below the root, at least 0; a unit not under the root (its chain
-- broken) gets 0. Development-stage data: the bodies are filled in place, not by a change at the effect point.
WITH RECURSIVE chain AS (
    SELECT id, 0 AS level FROM authz_record
     WHERE record_type = 'management_unit' AND coalesce((body->>'root')::boolean, false)
    UNION ALL
    SELECT r.id, c.level + 1 FROM authz_record r JOIN chain c ON r.body->>'parent' = c.id::text
     WHERE r.record_type = 'management_unit' AND c.level < 64
), levels AS (
    SELECT id, min(level) AS level FROM chain GROUP BY id
)
UPDATE authz_record r
   SET body = r.body || jsonb_build_object(
       'management_actions', '["grant", "revoke", "edit_role", "bind_role", "delegate_management", "share_governance"]'::jsonb,
       'max_subdelegation_depth', greatest(6 - coalesce(l.level, 6), 0))
  FROM authz_record x LEFT JOIN levels l ON l.id = x.id
 WHERE r.id = x.id AND r.record_type = 'management_unit' AND NOT r.body ? 'management_actions';
