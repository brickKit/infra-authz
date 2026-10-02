[English](AGENTS.md) · [中文](AGENTS.zh.md)

# infra/authz

The AI guide to developing this component. How to use it, its boundaries and contracts: BRICKKIT.md. Why it is shaped this way: `docs/design.md`. Dependencies, configuration and deployment: component.yaml.

## Code map

| Path | Owns |
|---|---|
| `backend/module/module.go` | The only entry, `New(ctx, rt)`: reads the configuration, builds repo → service → HTTP + gRPC; `Start` synchronises the permission catalogue, grants the bootstrap administrator, then runs the outbox pump and the partition loop |
| `backend/cmd/server/main.go` | One line, `besdk.RunStandalone(module.New)` |
| `backend/cmd/migrate/main.go` | One line, `migrate.Main(migrations.FS)`: the migration container's entry (`./migrate up`) |
| `backend/internal/service/catalog.go` | `ParsePermissionCatalog`: the registry TSV in `PERMISSION_CATALOG` → entries |
| `backend/internal/service/service.go` | Orchestration shared by REST and gRPC: catalogue sync, bootstrap admin, bundle window, `MyPermissions`, `ResolveClaims`, the three steps of "grant one person one permission" |
| `backend/internal/service/status.go` | Sentinel errors → gRPC status (the SDK maps those to HTTP) |
| `backend/internal/repo/bundle.go` | `ComputeBundle`: every role with its keys, plus `stale_since` from `role_changes` and expired `user_roles` |
| `backend/internal/repo/permissions.go` | `SyncPermissionCatalog`: upsert only, never delete |
| `backend/internal/repo/roles.go` | Roles and their keys; the personal role `u:<sub>` |
| `backend/internal/repo/userroles.go` | Grants with expiry; every change to a person's roles writes `role_changes` in the same transaction |
| `backend/internal/repo/departments.go` | The minimal department table behind the department path |
| `backend/internal/http/http.go` | REST routes, each registered with its permission key; the bundle's `ETag` |
| `backend/internal/grpc/grpc.go` | `infra.authz.v1.AuthzService` |
| `backend/internal/partition/` | Background loop creating weekly `event_outbox` and monthly `role_changes` partitions ahead |
| `migrations/` | SQL migrations, embedded by `migrations/embed.go`; `003` seeds `authz_admin` and `infra.authz.admin` |
| `contracts/` | proto, OpenAPI, event schema |
| `gen/infra/authz/` | Generated Go code: a nested Go module, tagged on its own as gen/infra/authz/v1.x.y and imported by infra/iam-casdoor; never edited by hand |
| `scripts/` | `seed.sh` / `seed-clean.sh` for local demo grants |

| Feature | Start here | Then |
|---|---|---|
| The format of `PERMISSION_CATALOG` | `backend/internal/service/catalog.go` | `backend/internal/service/catalog_test.go`, `backend/internal/repo/permissions.go` |
| What goes into the bundle | `backend/internal/repo/bundle.go` | `backend/internal/repo/repo_test.go` (`TestComputeBundle_*`) |
| Who becomes stale, and when | `backend/internal/repo/userroles.go` (`recordRoleChange`) | `backend/internal/repo/bundle.go` (`loadStaleSinceInto`) |
| A new admin endpoint | `backend/internal/http/http.go` (`RegisterRoutes`) | `backend/internal/service/service.go`, `contracts/authz.openapi.yaml` |
| Claims at login | `backend/internal/service/service.go` (`ResolveClaims`) | `backend/internal/grpc/grpc.go` |

## Build and test

```bash
# tests run against the test database brickkit_test_db, never brickkit_db (make test-db-init ID=infra/authz at the project root);
# TEST_PG_DSN=postgres://postgres:<password>@localhost:5432/brickkit_test_db?sslmode=disable
make test                    # every package ends in "ok"; refuses to run without TEST_PG_DSN
go test ./... -count=1 -v | grep -c -- '--- SKIP'   # 0: no test skipped
make check-version dag-check contract-check import-scan module-check   # each prints one ✓ line; contract-check compares with the last release tag
make docs-check              # "0 with errors, 0 warnings"
# migrations, as the login role:
PG_HOST=localhost PG_PORT=5432 PG_DATABASE=brickkit_test_db PG_USER=infra_authz_rw \
  PG_PASSWORD=… PG_SCHEMA=infra_authz make migrate-idempotent   # ✓ 迁移幂等
```

The core test is `TestComputeBundle_专属角色也出现在roles里`: rerun it after any change to the bundle. On a real machine, from the project root: `make verify ID=infra/authz ROUTE=/api/admin/roles FOCUS=1` builds the image, starts only this component, checks migration, health and the permission check, runs a focus run, and tears down.

## Design decisions

- **Not on the request path.** Components decide from their in-memory bundle; this component only computes and serves it. No component declares a dependency on it.
- **Plain unions, no deny.** "Everything except X" is a role without X.
- **Two kinds of change.** Changing what a role contains reaches everyone through the next poll (~15 s) and touches no token; changing who holds a role writes `role_changes` and makes that person's tokens stale.
- **Expiry needs no job.** `stale_since` reads past `user_roles.expires_at` inside the window directly.
- **The catalogue is the registry file itself** (`file://registry/permissions.tsv`), never a generated copy; the table mirrors it, `deprecated` included, and never deletes.
- **It eats its own bundle**: the admin API is protected by `infra.authz.admin` through the same SDK check, fed by `AUTHZ_BUNDLE_URL` pointing at itself. `/authz/bundle` stays public.

## Pitfalls

| Never | Symptom | Why |
|---|---|---|
| Filter `ComputeBundle` / `loadRolesInto` by `is_system` | People holding a personal role `u:<sub>` silently lose every permission in every component; no error anywhere | The token carries `u:<sub>`; if the bundle lacks it, the SDK expands it to nothing. `is_system` only hides roles from `ListRoles` |
| Write `role_changes` when a role's keys change | Every holder of the role is forced to refresh for nothing | Role content reaches components through the bundle; only a change to a person's roles needs `stale_since` |
| Add a job that writes `role_changes` on expiry | Duplicate stale entries; one more loop that can die | `loadStaleSinceInto` derives expiry from `user_roles.expires_at` |
| Delete keys in `SyncPermissionCatalog` that the catalogue no longer lists | Roles granted that key lose it (`ON DELETE CASCADE` on `role_permissions`); users suddenly get `403` | Keys are persistent identifiers; retire one with the registry's `deprecated` column |
| Scan `array_agg(...)` into `[]string` | `unsupported Scan, storing driver.Value type string into type *[]string` | pgx through `database/sql` does not decode `text[]`; collect rows in Go as `loadRolesInto` does |
| Compute `expires_at` with `time.Now()` on every grant call | Every repeated grant counts as a change and makes the person stale again | Idempotency compares the value literally; pass the business date |
| Give `PERMISSION_CATALOG` anything but the registry TSV (for example one comma-separated line of entries) | The component starts; the log has ERROR `同步权限目录失败` with `第 1 行只有 1 列`, and new keys never reach the table | The value is the registry file itself; write `file://<path>` |
| Add an entry to `dependencies.components` | `make dag-check` fails; with the edge, authz could not start before that component, and every protected route everywhere waits on it | Every component depends on authz through configuration only |
| Make `DeptPathFor` return `/` or the root department's path for a person with no department, to "keep them seeing everything" | Every new account, before anyone assigns it a department, sees every department's orders, opportunities and tasks | An empty path is the legal "no department" state and the SDK scopes it to the person's own rows; whoever must see the whole organisation is assigned to the root department (`scripts/seed.sh` does this for `dev.superuser`) |

## Before changing code

1. Am I filtering the bundle by `is_system`, or writing `role_changes` for role content or expiry? Stop: see Pitfalls.
2. Could this change delete or rename a released permission key? Keys are only added; retire with `deprecated`.
3. Contract change? Append only. Every component in the project polls the bundle and `infra/iam-casdoor` imports the gRPC package: this is the most widely consumed contract in the project.
4. Did `gen/` change? Then the contract package needs a new tag `gen/infra/authz/v1.x.y` and the root `go.mod` must require it, or `infra/iam-casdoor` and the shell compile against the old one.
5. A new REST route is registered with `besdk.GET` / `POST` / `DELETE` and `infra.authz.admin` (or `besdk.Authenticated` for "my own" data).
6. New rule → write the failing test first (real database for anything SQL), then the code.
7. Bump `metadata.version` before the first change after a release; update BRICKKIT.md and `docs/design.md` in the same commit as the code.

<!-- brickkit:managed:begin lang=en -->
<!-- maintained by brickkit (init, add, remove, upgrade, skills update): edits between these markers are overwritten -->

## BrickKit

This is a BrickKit component: `component.yaml` is all the platform reads. The rules it relies on:

- `configSchema` keys are the environment variable names the code reads. Never use a reserved name: `COMPONENT_ID`, `COMPONENT_VERSION`, `PORT`, `BRICKKIT_SERVED_MEMBERS`, `BRICKKIT_SERVED_MEMBERS_CONFIG`, or any `*_ENDPOINT`.
- Dependencies are exact versions. A dependency's address arrives as `<ID>_ENDPOINT`; an optional dependency that is absent has no variable at all, so read it with a fallback.
- `/healthz` checks only this process, never a dependency. The migration command runs from the same image and must fail on an argument it does not know.
- `BRICKKIT.md` travels to every project that uses this component and is read there without the repository: keep it in step with the code, with no relative links.
- Release: raise `metadata.version`, commit, push, `brickkit release`. `brickkit lint` checks the manifest and these docs — inside a project, run in this directory, it checks only this component (`--all` for the whole project).
- The full rules are in the `brickkit-component` skill (`.claude/skills/brickkit-component/SKILL.md` at the root of the project or repository where skills are installed; `brickkit skills update` installs it); for flags ask `brickkit <command> --help`; BrickKit's own documentation is `brickkit docs`.
<!-- brickkit:managed:end -->
