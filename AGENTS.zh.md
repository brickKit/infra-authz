[English](AGENTS.md) · [中文](AGENTS.zh.md)

# infra/authz

开发本组件的 AI 指南。用法、边界与契约：BRICKKIT.md；为什么长这样：`docs/design.md`；依赖、配置与部署：component.yaml。

## 代码地图

| 路径 | 负责 |
|---|---|
| `backend/module/module.go` | 唯一入口 `New(ctx, rt)`：读配置，组装 repo → service → HTTP + gRPC；`Start` 先同步权限目录、授予自举管理员，再跑 Outbox 推送与分区维护 |
| `backend/cmd/server/main.go` | 一行 `besdk.RunStandalone(module.New)` |
| `backend/cmd/migrate/main.go` | 一行 `migrate.Main(migrations.FS)`：迁移容器的入口（`./migrate up`） |
| `backend/internal/service/catalog.go` | `ParsePermissionCatalog`：`PERMISSION_CATALOG` 里的登记表 TSV → 条目 |
| `backend/internal/service/service.go` | REST 与 gRPC 共用的编排：目录同步、自举管理员、bundle 窗口、`MyPermissions`、`ResolveClaims`、"给一个人单独加一个权限"的三步 |
| `backend/internal/service/status.go` | 哨兵错误 → gRPC status（SDK 再映射成 HTTP） |
| `backend/internal/repo/bundle.go` | `ComputeBundle`：全部角色及其权限键，加上来自 `role_changes` 与已到期 `user_roles` 的 `stale_since` |
| `backend/internal/repo/permissions.go` | `SyncPermissionCatalog`：只 upsert，绝不删除 |
| `backend/internal/repo/roles.go` | 角色及其权限键；专属角色 `u:<sub>` |
| `backend/internal/repo/userroles.go` | 带到期时间的角色分配；人的角色每变一次，同一事务里写一行 `role_changes` |
| `backend/internal/repo/departments.go` | 部门路径背后的极简部门表 |
| `backend/internal/http/http.go` | REST 路由，每条都带权限键注册；bundle 的 `ETag` |
| `backend/internal/grpc/grpc.go` | `infra.authz.v1.AuthzService` |
| `backend/internal/partition/` | 后台循环：提前建 `event_outbox` 周分区与 `role_changes` 月分区 |
| `migrations/` | SQL 迁移，由 `migrations/embed.go` 嵌入；`003` 种下 `authz_admin` 与 `infra.authz.admin` |
| `contracts/` | proto、OpenAPI、事件 schema |
| `gen/infra/authz/` | 生成的 Go 代码：独立的嵌套 Go 模块，单独打 tag gen/infra/authz/v1.x.y，infra/iam-casdoor import 它；绝不手改 |
| `scripts/` | 本地演示授权用的 `seed.sh` / `seed-clean.sh` |

| 功能 | 从这里开始 | 然后 |
|---|---|---|
| `PERMISSION_CATALOG` 的格式 | `backend/internal/service/catalog.go` | `backend/internal/service/catalog_test.go`、`backend/internal/repo/permissions.go` |
| bundle 里有什么 | `backend/internal/repo/bundle.go` | `backend/internal/repo/repo_test.go`（`TestComputeBundle_*`） |
| 谁、什么时候变 stale | `backend/internal/repo/userroles.go`（`recordRoleChange`） | `backend/internal/repo/bundle.go`（`loadStaleSinceInto`） |
| 新增一个管理接口 | `backend/internal/http/http.go`（`RegisterRoutes`） | `backend/internal/service/service.go`、`contracts/authz.openapi.yaml` |
| 登录时的 claims | `backend/internal/service/service.go`（`ResolveClaims`） | `backend/internal/grpc/grpc.go` |

## 构建与测试

```bash
# 测试连测试库 brickkit_test_db，绝不连 brickkit_db（项目根 make test-db-init ID=infra/authz 准备）；
# TEST_PG_DSN=postgres://postgres:<口令>@localhost:5432/brickkit_test_db?sslmode=disable
make test                    # 每个包都以 "ok" 结尾；没设 TEST_PG_DSN 时拒绝运行
go test ./... -count=1 -v | grep -c -- '--- SKIP'   # 0：没有跳过的测试
make check-version dag-check contract-check import-scan module-check   # 各打印一行 ✓；contract-check 对比上一个发布 tag
make docs-check              # "0 with errors, 0 warnings"
# 迁移，以登录角色运行：
PG_HOST=localhost PG_PORT=5432 PG_DATABASE=brickkit_test_db PG_USER=infra_authz_rw \
  PG_PASSWORD=… PG_SCHEMA=infra_authz make migrate-idempotent   # ✓ 迁移幂等
```

核心测试是 `TestComputeBundle_专属角色也出现在roles里`：改了 bundle 就重跑它。真机上，在项目根：`make verify ID=infra/authz ROUTE=/api/admin/roles FOCUS=1` 构建镜像、只起本组件、核对迁移、健康与权限判定、跑一次 focus，然后收尾。

## 设计取舍

- **不在请求路径上。** 各组件用内存里的 bundle 判定，本组件只负责算出来、发出去。没有组件对它声明依赖。
- **纯并集，没有拒绝。** "除了 X 都能做"就是一个不含 X 的角色。
- **两类变化。** 改角色的内容，下一次轮询（约 15 秒）就到达所有人，不碰任何 token；改谁持有角色，写 `role_changes`，让这个人的 token 变 stale。
- **到期不需要任务。** `stale_since` 直接读窗口内已经过去的 `user_roles.expires_at`。
- **目录就是登记表文件本身**（`file://registry/permissions.tsv`），不是生成的副本；表是它的镜像，含 `deprecated`，从不删除。
- **自己吃自己的 bundle**：管理 API 用同一套 SDK 判定 `infra.authz.admin`，判定数据来自指向自己的 `AUTHZ_BUNDLE_URL`。`/authz/bundle` 保持公开。

## 易错点

| 不许 | 症状 | 为什么 |
|---|---|---|
| 在 `ComputeBundle` / `loadRolesInto` 里按 `is_system` 过滤 | 持有专属角色 `u:<sub>` 的人在所有组件里静默失去全部权限，任何地方都没有报错 | token 里带着 `u:<sub>`，bundle 里没有它，SDK 展开出来就是空集。`is_system` 只用来在 `ListRoles` 里隐藏角色 |
| 角色的权限键变化时写 `role_changes` | 这个角色的每个持有者都被白白逼着刷新 | 角色内容经 bundle 到达各组件；只有人的角色变了才需要 `stale_since` |
| 加一个在到期时写 `role_changes` 的任务 | stale 记录重复；又多一个会死的循环 | `loadStaleSinceInto` 从 `user_roles.expires_at` 推导到期 |
| 在 `SyncPermissionCatalog` 里删掉目录里不再列出的键 | 授过这个键的角色随之失去它（`role_permissions` 上 `ON DELETE CASCADE`），用户突然 `403` | 键是持久标识；退役用登记表的 `deprecated` 列 |
| 把 `array_agg(...)` 直接 Scan 进 `[]string` | `unsupported Scan, storing driver.Value type string into type *[]string` | pgx 经 `database/sql` 不解码 `text[]`；像 `loadRolesInto` 那样在 Go 里逐行收集 |
| 每次授权都用 `time.Now()` 现算 `expires_at` | 每次重复授权都算一次变化，这个人一再变 stale | 幂等按值逐字比较；传业务上的到期日 |
| 给 `PERMISSION_CATALOG` 登记表 TSV 以外的值（例如一行逗号分隔的条目） | 组件照常启动；日志里有 ERROR `同步权限目录失败`，带 `第 1 行只有 1 列`，新键永远进不了表 | 值就是登记表文件本身；写 `file://<路径>` |
| 往 `dependencies.components` 加一条 | `make dag-check` 失败；有了这条边，authz 要等那个组件先起来，所有组件的受保护路由都跟着等 | 所有组件都只经配置依赖 authz |
| 为了"让没分部门的人照样看全部"，让 `DeptPathFor` 对没有部门的人返回 `/` 或根部门的路径 | 每个新账号在有人给它分部门之前，都看得到所有部门的订单、商机与待办 | 空路径是合法的"没有部门"状态，SDK 把它限定为此人自己的行；要看全公司的人分到根部门（`scripts/seed.sh` 就是这样给 `dev.superuser` 分的） |

## 改代码前自查

1. 我是不是在按 `is_system` 过滤 bundle，或者为角色内容 / 到期写 `role_changes`？停下：见易错点。
2. 这次改动会不会删除或改名一个已发布的权限键？键只增加；退役用 `deprecated`。
3. 契约变更？只增不改。项目里每个组件都轮询 bundle，`infra/iam-casdoor` import gRPC 包：这是项目里消费面最广的契约。
4. `gen/` 变了？契约包要打新 tag `gen/infra/authz/v1.x.y`，根 `go.mod` 要 require 它，否则 `infra/iam-casdoor` 与外壳对着旧的编译。
5. 新 REST 路由用 `besdk.GET` / `POST` / `DELETE` 注册，带 `infra.authz.admin`（"我自己的"数据用 `besdk.Authenticated`）。
6. 新规则 → 先写会失败的测试（涉及 SQL 的用真实数据库），再写代码。
7. 发布后的第一个改动之前先升 `metadata.version`；BRICKKIT.md 与 `docs/design.md` 与代码在同一个提交里更新。
