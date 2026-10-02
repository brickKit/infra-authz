[English](design.md) · [中文](design.zh.md)

# infra/authz design

Conclusions only, for whoever changes this component's design. How to use it: `BRICKKIT.md`; how the code is laid out: `AGENTS.md`.

## Boundaries

This component is the bookkeeper of the permission system: the permission-key catalogue, roles as plain unions of keys, who holds which role, and the policy bundle computed from them. It is the only part of the permission system that keeps state; the decision itself happens in every component's process, against an in-memory copy of the bundle.

| Not here | Owner | Why |
|---|---|---|
| Identity, passwords, login, OIDC, token issuing | Casdoor + `infra/iam-casdoor` | This component only knows the `sub` string. Swapping the identity provider then moves no role data |
| The per-request permission decision | the SDK in each component | A central decision point on every request is a Zanzibar-style service; it does not fit "one customer, one machine", and it would put this component on every request's path |
| Row-level data scopes | each component's `assembly.yaml` and code | Data scopes ship with the component version; they are not configured here |
| Organisation master data (departments, positions, reporting lines) | an organisation master-data component | Only the department path string is needed here; the department table is a stopgap until that component exists |
| Menus | each component's `assembly.yaml`, aggregated by the assembly tooling | There is no central menu table |
| The audit log | an audit component | This component would publish events; the audit component stores them |

## Owned data

| Table | Partitioned | Notes |
|---|---|---|
| `permissions` | no | `key` primary key; `title`, `type`, `owner_component`, `deprecated`. A mirror of the registry, upserted at every start; rows are never deleted |
| `roles` | no | `code` is the natural primary key (the bundle is keyed by it); `is_system` marks the personal roles `u:<sub>` and the bootstrap role `authz_admin` |
| `role_permissions` | no | `(role_code, permission_key)`; both foreign keys `ON DELETE CASCADE` |
| `user_roles` | no | `(sub, role_code)`; `expires_at` null means never. The only table that grows with the number of users; it is not in the bundle |
| `role_changes` | monthly, by `changed_at` | `granted` / `revoked` / `kicked`; the source of `stale_since`. Written in the same transaction as the `user_roles` change |
| `departments`, `user_departments` | no | the department tree (`dept_path` contains the department's own ID, for example `/1/12/`) and sub → department |
| `event_outbox` | weekly, by `created_at` | the outbox the pump publishes from; no `event_inbox` (nothing is consumed) |

Terminal states: a `role_changes` row is final when written; an expired `user_roles` row stays in the table (who had what, when) but no longer counts. Migration `003` creates the key `infra.authz.admin`, the role `authz_admin` and the link between them; who receives that role is deployment-specific and done at start from `BOOTSTRAP_ADMIN_SUB`, because migrations must not depend on runtime configuration.

**The catalogue comes from the registry itself.** `PERMISSION_CATALOG` is the content of `registry/permissions.tsv`, given as `file://registry/permissions.tsv`. The alternative — the assembly tooling generating a catalogue file — adds a "remember to regenerate after adding a key" step, and a missed regeneration means a new key silently never reaches the table. Reading the registry directly has no such step: after a key is appended, the next `brickkit up` recreates the component and it synchronises. Lines are tab-separated, at least four columns; the header, empty lines and `#` lines are skipped; a short line or an empty key fails the whole synchronisation with its line number. Rows with a non-empty `deprecated` are synchronised like the others, `deprecated` included: a retired key that some role still holds must keep resolving.

## Contract surface

gRPC `infra.authz.v1.AuthzService`:

| rpc | Kind | Notes |
|---|---|---|
| `ResolveClaims` | read | for `infra/iam-casdoor`: sub → roles, department path, organisation ID (`DEFAULT_ORG_ID`, one per deployment). Called at every login and every refresh and never cached: application tokens are signed from its answer, so a stale token refreshed once carries the current roles |
| `GetBundle` | read | the same bundle as REST, for callers that prefer gRPC |
| `BatchGetRoles` | read | roles by code in one call; unknown codes are left out; any other error is returned |

REST, at bare paths (not under `/infra/authz`): `/api/me/permissions` and `/api/admin/**` are platform-wide paths, independent of which component serves them.

- `GET /authz/bundle` — public, internal only: it is not in `edge_routes`, so the gateway route table never exposes it. It is the data every permission check depends on, so it cannot be protected by a permission check itself. Computed on every request (roles and their keys are hundreds of rows; `stale_since` reads a bounded window), with an `ETag` that is the SHA-256 of the body; `If-None-Match` equal to it → `304`.
- `GET /api/me/permissions` — `besdk.Authenticated`: the union of the caller's keys, read from the database rather than from the component's own bundle (no 15-second lag for "what can I do now"). The `sub` comes from the verified token only.
- `/api/admin/**` — every route behind `infra.authz.admin`: roles (list without personal roles, create, get, delete; grant / revoke a key), a person's roles (list current, grant with optional expiry, revoke), "grant one person one key" (ensures the personal role `u:<sub>`, adds the key, grants the role; each step idempotent, a retry completes a partial run), `revoke` (remove all of a person's roles, one `kicked` row), departments (list, create) and a person's department.

Writes are idempotent by construction (upserts and deletes), not by idempotency keys: granting the same role with the same expiry twice changes nothing and writes no `role_changes`; revoking what is not there writes nothing. There are no status endpoints: no component writes here as part of its own transaction.

**Stale tokens.** The bundle's `stale_since` maps a `sub` to the latest change to that person's roles within twice the access-token lifetime (`ACCESS_TOKEN_TTL_SECONDS`, which must equal the IAM adapter's): `granted`, `revoked`, `kicked` from `role_changes`, and expiries from `user_roles.expires_at` that fall in the window and are past. A token issued before that time gets `401 token_stale`, the frontend refreshes, and `ResolveClaims` returns the current roles. Older changes need no entry: any token issued before them has expired. Changing which keys a role holds does not make anyone stale: tokens carry roles, not keys, and the new keys arrive with the next poll. Changing a person's department does not either: the new path arrives at the next refresh, at most one token lifetime later.

## Events

Declared in `contracts/events/authz.events.json`: `infra.authz.role.changed.v1` (a role created, deleted, or its keys changed) and `infra.authz.user_role.changed.v1` (a person's roles granted, revoked, expired, kicked). Both are audit-only side events: the bundle never depends on them, because polling is stateless, idempotent and converges by itself, while event-driven distribution would need every component to consume, store, and handle reordering and replay.

This version writes neither event to the outbox; the outbox table and pump exist, and nothing consumes these subjects yet. See Open questions.

Consumed: none.

## Dependencies

None. Expected but absent:

| Not a dependency | Why |
|---|---|
| `infra/iam-casdoor` | The call goes the other way: the IAM adapter calls `ResolveClaims` here. This component knows only `sub` strings |
| every business component | They reach this component through `AUTHZ_BUNDLE_URL`, configuration, not an edge. An edge from every component would tie start-up order together for nothing; fail-static polling makes order irrelevant |
| the audit component | Events, not calls |
| an organisation master-data component | It does not exist; the department table stands in for it. When it exists it becomes an optional dependency or an event source |
| `infra/authz` itself | The admin API checks `infra.authz.admin` against the bundle at `AUTHZ_BUNDLE_URL`, which points at this component: the same check as everywhere else, not a special case |

## Place in the synchronous call graph

Not in it. No component has a synchronous edge to this one or from it. The one call that does happen, `infra/iam-casdoor` → `ResolveClaims`, is on the login and refresh path, not on a business request's path. Every component polls the bundle over HTTP every 15 seconds; that is configuration plus a background loop, not a call graph edge. It is unrelated to the three hubs and to "no synchronous edge between CRM and ERP".

## Partitioning and archiving

| Data | Hot | Archived |
|---|---|---|
| `permissions`, `roles`, `role_permissions` | always | never |
| `user_roles` | always | never; expired rows stay for "what did they have then" |
| `role_changes` | the last 2 × token lifetime | intended after seven days to `infra_authz_archive`; no archiving job exists yet, the monthly partitions simply accumulate (see Open questions) |
| `event_outbox` | weekly partitions | rolls forward with the partitions |

Only the last two token lifetimes of `role_changes` take part in `stale_since`, which keeps the list short (single digits to tens of entries) and the bundle small however many changes the table holds. The component creates `event_outbox` partitions four weeks ahead and `role_changes` partitions three months ahead, once at start and every 24 hours.

## Data scopes

None (`data_scopes: none`). Whoever may open the role management pages (`infra.authz.admin`) sees all roles, grants and departments: that is a function permission. Restricting it by department would be a data scope on the permission data itself, which nobody needs and which would make "who can grant what" depend on the organisation tree.

## Reference implementations

| Project | Version | Module consulted | What was borrowed | License | Usage |
|---|---|---|---|---|---|
| Open Policy Agent | v0.68 (documentation) | Bundle API: `ETag` conditional fetch, fail-static on fetch failure | The whole distribution model: the policy goes to each process, decisions happen in memory, a failed fetch keeps the last policy | Apache-2.0 | Borrowed reasoning |
| Kubernetes RBAC | documentation | `rbac/v1` Role / RoleBinding | Plain unions without deny, and the stated reason (rules stay easy to reason about) | Apache-2.0 | Borrowed reasoning |
| Casbin | documentation | RBAC with domains | Read only for how models are layered; not adopted: the model here is far simpler, and the library would be one more indirection | Apache-2.0 | Borrowed reasoning |
| Salesforce | — | Profile / Permission Set | "A baseline plus stackable permission sets"; and the cost of its sharing-table recalculation, the reason data scopes live in component versions instead | proprietary | Borrowed from practice |
| AWS IAM | — | policy evaluation, eventual consistency | As a counter-example for deny/allow evaluation order; and "a policy change takes effect within seconds" as the bar for the 15-second poll | proprietary | Borrowed from practice |

**Deliberately avoided**: Zanzibar / SpiceDB / OpenFGA relation tuples — they model "each resource has its own ACL" (document sharing), while ERP visibility is "by organisational slices"; tuples would mean an ACL row per document, and their performance relies on many machines. SAP's authorization objects mixing function and data permissions (they change at different rates: daily against by policy). Putting all permission keys in the JWT (an administrator's full set overflows request headers: login works, then every request fails with `431`). Odoo's `ir.rule` domain expressions injected by the ORM (no ORM here; runtime strings an AI can neither read nor test).

No slot family: the five common data-scope levels are the same across mature ERPs; what differs is which dimensions a component scopes by, and that is declared in each component's `assembly.yaml`.

## Open questions

| Question | Current answer |
|---|---|
| Should the two declared audit events be emitted, with what `version` (roles and grants have no version column)? | Not emitted in this version and nothing consumes them; deciding the version semantics is a contract decision for when the audit component is built |
| How do the department tables move to the organisation master-data component, and how are the two `dept_path`s kept in line while both exist? | Open until that component is designed |
| How big does the bundle get with a real customer's roles? | Estimated tens of kilobytes; above about 1 MB, split it by component prefix |
| Do `role_changes` (seven-day window here) and the audit component's long-term log overlap? | Open until the audit component exists; until then no archiving job is written and the partitions accumulate (a few rows per change) |
| Can `scripts/seed.sh` grant the seed super-user through the admin API instead of writing to the database? | Only when `BOOTSTRAP_ADMIN_SUB` already holds that user's `sub` — which needs the IAM seed user created first, its `sub` put in `.env`, and this component restarted before seeding. Local development leaves `BOOTSTRAP_ADMIN_SUB` empty, so step ① keeps writing the first role directly; every later step uses the admin API |
| The admin API can delete `authz_admin` or a personal role like any other role | Allowed today; a guard on `is_system` roles is a behaviour change to decide with the frontend's role pages |
| `MyPermissions` skips a role it cannot read (deleted between two queries) and also any other read error, returning a partial set | Accepted: the answer only drives which buttons the frontend shows, and every action is checked again server-side |
