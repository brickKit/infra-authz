# infra/authz

## Purpose

The bookkeeper of the permission system. It keeps the permission-key catalogue, the roles (each a plain union of permission keys, no deny rules) and who holds which role, and turns them into one small policy bundle that every component polls and checks against in memory. It is not on the path of any user request's permission check: each component decides locally from its last copy of the bundle.

**Owns**

- The `permissions` table: a mirror of the project's permission-key registry, synchronised from `PERMISSION_CATALOG` at every start. Keys are only ever added or updated, never deleted; a retired key keeps its row with the registry's `deprecated` text.
- Roles (`roles`, `role_permissions`), including the personal role `u:<sub>` that backs "give this one person one extra permission", and the bootstrap role `authz_admin` holding `infra.authz.admin` (created by a migration).
- Role grants (`user_roles`, optionally with an expiry) and the bounded list of recent grant changes (`role_changes`) that makes already-issued tokens stale.
- The bundle served at `GET /authz/bundle`: role → permission keys, plus `stale_since` (sub → time of the latest change to that person's roles within twice the access-token lifetime).
- Login-time claims: `ResolveClaims` gives the IAM adapter a person's roles, department path and organisation ID.
- A minimal department table (`departments`, `user_departments`) that exists only to give `ResolveClaims` a department path. A path holds the department's ancestors and itself, `/<id>/…/`: a top-level department is `/<id>/`, never `/`. A person assigned to no department gets an empty string. The SDKs (`be-sdk-go`, `be-sdk-python`, `be-sdk-ts`) from v0.5.0 read an empty path as "no department", not as the whole tree: the `org` dimension of a data scope matches no row and only the person's own rows remain. `/` is the explicit marker for the whole tree; this component never issues it.

**Does not own**

- Identity, passwords, login and token issuing: `infra/iam-casdoor` in front of Casdoor. This component only knows the `sub` string.
- The per-request permission decision: the SDK inside each component, from its in-memory copy of the bundle.
- Row-level data scopes ("sales sees only their own orders"): each component's `assembly.yaml` and code. This component has none (`data_scopes: none`).
- Organisation master data (departments, positions, reporting lines): an organisation master-data component. The department table here is a stopgap for one string.
- Menus: each component's `assembly.yaml`, aggregated by the assembly tooling.
- The audit log: an audit component. Two audit events are declared in the contract but not emitted yet (see Contracts).

## Before you deploy

- **PostgreSQL**: a schema `infra_authz`, plus `infra_authz_archive` if your schema convention creates one (this component never writes to it). A login role `infra_authz_rw` with `USAGE` and `CREATE` on `infra_authz`, and its password. The migration runs as this role and creates the tables, so the role owns them; that matters because the running component creates the weekly partitions of `event_outbox` and the monthly partitions of `role_changes` itself. BrickKit creates none of this; in the BrickEnterprise assembly project `make dev-env` writes the password into `.env` and `make db-init` creates the schemas, role and grants.
- **The permission-key registry** as a tab-separated file with the header `key title type owner_component deprecated`, given to `PERMISSION_CATALOG` as `file://<path>` (in the BrickEnterprise project `file://registry/permissions.tsv`). It is read when the deployment files are generated; after a key is added, the next `brickkit up` recreates this component and the key is synchronised at start. Nothing else needs regenerating.
- **The first administrator**: put the deployer's `sub` in `BOOTSTRAP_ADMIN_SUB`; at start the component grants them `authz_admin` (idempotent). Left empty, nobody can use the admin API until someone grants `authz_admin` directly in the database.
- **NATS** reachable at `NATS_URL`: the outbox pump publishes from it. The component starts without NATS reachable.
- **Departments**: assign everyone who must see a department's data (orders, opportunities, tasks scoped by `dept_path`) to that department, and whoever must see the whole organisation to its root department (`POST /api/admin/users/{sub}/department`). A person left without a department sees only their own rows in every department-scoped list, never everyone's. A new assignment reaches the token at the next refresh, at most `ACCESS_TOKEN_TTL_SECONDS` later.
- **Identity** (`infra/iam-casdoor`, or any IAM serving a JWKS) reachable at `IAM_JWKS_URL`, and `AUTHZ_BUNDLE_URL` pointing at this component's own bundle: the admin API is protected by the same check as every other component, fed by its own bundle. For the first seconds after start, until its own first poll succeeds, the admin API answers `503`.
- Demo data (optional): `make seed` in the component directory, once this component, Casdoor and `infra/iam-casdoor`'s seed users exist, grants the seed user `dev.superuser` every permission key and assigns them to the root department (head office), builds a small department tree (head office → East China, South China) and three job roles, and assigns the other seed users to them; `dev.finance.viewer` stays without a department on purpose, because finance scopes by legal entity, not by department.

## Dependencies

None. Every other component reaches this one through configuration (`AUTHZ_BUNDLE_URL`), not a dependency edge, so start-up order does not matter: a component that cannot reach the bundle keeps using its last copy (fail-static), or fails closed if it never had one. The direction to the IAM adapter is the reverse: `infra/iam-casdoor` calls `ResolveClaims` here; this component never calls it.

The bundle and the JWKS are fetched from the URLs in the configuration. Without them every protected route fails closed: no or invalid token → `401`; a token issued before the person's latest role change → `401` with `token_stale`; `IAM_JWKS_URL` empty or unreachable → `403`; the bundle never fetched yet → `503`; a valid user without the permission key → `403`. `/healthz` stays `200` throughout: it reports only that this process is alive.

## Configuration

| Variable | Meaning |
|---|---|
| `PG_HOST` | PostgreSQL host. Usually the project's shared value (`$var:PG_HOST`). |
| `PG_PORT` | PostgreSQL port; default `5432`. |
| `PG_DATABASE` | The database holding the `infra_authz` schema (`$var:PG_DATABASE`). |
| `PG_USER` | The login role, `infra_authz_rw` as a literal. Inside a shell the shell logs in with its own role and switches to this one per transaction (`SET LOCAL ROLE`), so the role name must be `<PG_SCHEMA>_rw`. |
| `PG_PASSWORD` | Password of `PG_USER`. Secret: write `${INFRA_AUTHZ_DB_PASSWORD}` (or your secret store's reference), never the value. |
| `PG_SCHEMA` | Schema of all tables, the outbox and the migration state table (`schema_migrations_infra_authz`); default `infra_authz`. Write the literal anyway so every component's schema is visible in one place. |
| `NATS_URL` | NATS server the outbox pump publishes to (`$var:NATS_URL`). |
| `OTEL_BASE_URL` | OpenTelemetry collector base URL; empty (the default) exports nothing. |
| `AUTHZ_BUNDLE_URL` | This component's own bundle, for example `http://infra-authz-2-0-1:8223/authz/bundle`: the admin API checks `infra.authz.admin` against it. Required. Every other component points at the same URL; change it everywhere when this component's version changes. |
| `IAM_JWKS_URL` | URL of the JWKS used to verify user tokens locally, for example `http://infra-iam-casdoor-2-0-0:8200/.well-known/jwks.json`. Required. |
| `PERMISSION_CATALOG` | The permission-key registry as text: tab-separated, one key per line, columns `key`, `title`, `type`, `owner_component`, `deprecated` (the last may be empty or missing); empty lines, lines starting with `#` and the header line are skipped. Write `file://<path to the registry>` so the value is always the file itself. Required, no default. A line with fewer than four columns or an empty key makes the whole synchronisation fail with the line number in the ERROR log `同步权限目录失败`; the table keeps what it had. |
| `ACCESS_TOKEN_TTL_SECONDS` | Lifetime of the application access token the IAM adapter issues; default `600`. `stale_since` covers changes within twice this value, so it must equal the IAM adapter's token lifetime. |
| `DEFAULT_ORG_ID` | The organisation ID `ResolveClaims` returns for everyone; default `1` (one organisation per deployment). |
| `BOOTSTRAP_ADMIN_SUB` | `sub` of the first administrator, granted `authz_admin` at every start (idempotent); default empty (nobody). In the BrickEnterprise project `${INFRA_AUTHZ_BOOTSTRAP_ADMIN_SUB:-}`. |

## Contracts

- `contracts/infra/authz/v1/authz.proto` — gRPC `infra.authz.v1.AuthzService`: `ResolveClaims` (sub → roles, department path, organisation ID; called by the IAM adapter at every login and refresh, never cached), `GetBundle` (the same bundle as REST), `BatchGetRoles` (roles by code; unknown codes are left out, not an error). The Go package is the separate module `github.com/brickKit/infra-authz/gen/infra/authz`, which `infra/iam-casdoor` imports.
- `contracts/authz.openapi.yaml` — REST at bare paths, not under `/infra/authz`: `GET /authz/bundle` (public, internal network only, not an edge route; `ETag` and `If-None-Match` → `304`), `GET /api/me/permissions` (any signed-in user; the caller's own keys, from the token's `sub`), and behind `infra.authz.admin`: `GET`/`POST /api/admin/roles`, `GET`/`DELETE /api/admin/roles/{code}`, `POST /api/admin/roles/{code}/permissions`, `DELETE /api/admin/roles/{code}/permissions/{key}`, `GET`/`POST /api/admin/users/{sub}/roles`, `DELETE /api/admin/users/{sub}/roles/{code}`, `POST /api/admin/users/{sub}/permissions` (through the personal role), `POST /api/admin/users/{sub}/revoke` (remove all roles), `GET`/`POST /api/admin/departments`, `POST /api/admin/users/{sub}/department`.
- `contracts/events/authz.events.json` — declares `infra.authz.role.changed.v1` and `infra.authz.user_role.changed.v1`, audit-only side events. This version does not emit them yet; nothing consumes them. The bundle never depends on events: changes reach components by polling. No events are consumed.
- `assembly.yaml` — this project's metadata: the permission key `infra.authz.admin`, the menu entry, the edge routes `/api/me/permissions` and `/api/admin/**`, the schema and role, and `data_scopes: none`.

## Shell declaration

Not a shell. It can be hosted in a Go shell (in the BrickEnterprise project, `be/go-infra`) or run on its own; the code is the same either way. Inside a shell, `AUTHZ_BUNDLE_URL` keeps this component's own service name.
