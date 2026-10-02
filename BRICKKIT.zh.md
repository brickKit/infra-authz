# infra/authz

## 组件定位

权限体系的账房。它保存权限键目录、角色（每个角色就是一组权限键的并集，没有拒绝规则）和谁持有哪个角色，并把它们算成一份很小的策略 bundle，供每个组件轮询、在内存里判定。它不在任何用户请求的判权限路径上：每个组件用自己手里最后一份 bundle 在本地判定。

**拥有**

- `permissions` 表：项目权限键登记表的镜像，每次启动从 `PERMISSION_CATALOG` 同步。键只增加或更新，绝不删除；退役的键保留原行，带上登记表的 `deprecated` 说明。
- 角色（`roles`、`role_permissions`），包括支撑"给某一个人单独加一个权限"的专属角色 `u:<sub>`，以及由迁移建好的自举角色 `authz_admin`（持有 `infra.authz.admin`）。
- 角色分配（`user_roles`，可带到期时间），以及让已签发 token 变 stale 的近期分配变更有界列表（`role_changes`）。
- `GET /authz/bundle` 下发的 bundle：角色 → 权限键，加上 `stale_since`（sub → 两倍 access token 有效期之内此人角色最近一次变化的时间）。
- 登录期 claims：`ResolveClaims` 给 IAM 适配层返回一个人的角色、部门路径与组织 ID。
- 一张极简部门表（`departments`、`user_departments`），只为给 `ResolveClaims` 提供部门路径。

**不拥有**

- 身份、密码、登录与签发 token：归 Casdoor 前面的 `infra/iam-casdoor`。本组件只认 `sub` 这个字符串。
- 每次请求的权限判定：归每个组件里的 SDK，用它内存里的 bundle 副本判定。
- 行级数据范围（"销售只看自己的订单"）：归各组件的 `assembly.yaml` 与代码。本组件自己没有（`data_scopes: none`）。
- 组织主数据（部门、岗位、汇报线）：归组织主数据组件。这里的部门表只是为一个字符串的权宜之计。
- 菜单：归各组件的 `assembly.yaml`，由装配工具汇总。
- 审计日志：归审计组件。契约里声明了两个审计事件，但还没有发出（见契约索引）。

## 部署前准备

- **PostgreSQL**：schema `infra_authz`；如果你的 schema 约定会建 `infra_authz_archive` 也可以建（本组件从不写它）。登录角色 `infra_authz_rw`，在 `infra_authz` 上有 `USAGE` 与 `CREATE`，以及它的密码。迁移以这个角色运行并建表，所以表归它所有——这一点有用：运行中的组件会自己给 `event_outbox` 建周分区、给 `role_changes` 建月分区。brickKit 不建这些；在 BrickEnterprise 装配项目里，`make dev-env` 把密码写进 `.env`，`make db-init` 建 schema、角色与授权。
- **权限键登记表**：制表符分隔的文件，表头 `key title type owner_component deprecated`，以 `file://<路径>` 的形式交给 `PERMISSION_CATALOG`（BrickEnterprise 项目里是 `file://registry/permissions.tsv`）。生成部署文件时读取；新增一个键之后，下一次 `brickkit up` 会重建本组件，启动时同步进去。不需要再生成任何东西。
- **第一个管理员**：把部署者的 `sub` 写进 `BOOTSTRAP_ADMIN_SUB`，启动时组件把 `authz_admin` 授给他（幂等）。留空时，在有人直接在数据库里授予 `authz_admin` 之前，没有人能用管理 API。
- **NATS** 可经 `NATS_URL` 访问：Outbox 后台循环从这里推送。NATS 不可达时组件照常启动。
- **身份**（`infra/iam-casdoor`，或任何提供 JWKS 的 IAM）可经 `IAM_JWKS_URL` 访问；`AUTHZ_BUNDLE_URL` 指向本组件自己的 bundle：管理 API 与所有组件用同一套判定保护，判定数据来自自己下发的 bundle。启动后最初几秒，在自己的第一次轮询成功之前，管理 API 回 `503`。
- 演示数据（可选）：本组件、Casdoor 与 `infra/iam-casdoor` 的种子用户都就绪后，在组件目录 `make seed`：给种子用户 `dev.superuser` 授予全部权限键，建一棵小部门树和三个岗位角色，并把其余种子用户分到其中。

## 依赖说明

无。别的组件都经配置（`AUTHZ_BUNDLE_URL`）找到本组件，不是依赖边，所以启动顺序无关紧要：拉不到 bundle 的组件沿用手里最后一份（fail-static），从来没拉到过就失败关闭。与 IAM 适配层的方向相反：是 `infra/iam-casdoor` 调这里的 `ResolveClaims`，本组件从不调它。

bundle 与 JWKS 从配置里的 URL 拉取。没有它们时每条受保护路由都失败关闭：没有或无效的 token → `401`；token 签发于此人最近一次角色变化之前 → `401`，带 `token_stale`；`IAM_JWKS_URL` 为空或不可达 → `403`；还没拉到过 bundle → `503`；合法用户但没有这个权限键 → `403`。`/healthz` 始终 `200`：它只报告本进程活着。

## 配置指南

| 变量 | 含义 |
|---|---|
| `PG_HOST` | PostgreSQL 主机。通常是项目共享值（`$var:PG_HOST`）。 |
| `PG_PORT` | PostgreSQL 端口；默认 `5432`。 |
| `PG_DATABASE` | 存放 `infra_authz` schema 的数据库（`$var:PG_DATABASE`）。 |
| `PG_USER` | 登录角色，字面量 `infra_authz_rw`。进外壳后由外壳以自己的角色登录、每个事务切到这个角色（`SET LOCAL ROLE`），所以角色名必须是 `<PG_SCHEMA>_rw`。 |
| `PG_PASSWORD` | `PG_USER` 的密码。密钥：写 `${INFRA_AUTHZ_DB_PASSWORD}`（或你的密钥库引用），绝不写值。 |
| `PG_SCHEMA` | 全部表、Outbox 与迁移状态表（`schema_migrations_infra_authz`）所在的 schema；默认 `infra_authz`。仍然写字面量，好让每个组件的 schema 在一处看得见。 |
| `NATS_URL` | Outbox 后台循环推送到的 NATS（`$var:NATS_URL`）。 |
| `OTEL_BASE_URL` | OpenTelemetry collector 基地址；为空（默认）时什么都不导出。 |
| `AUTHZ_BUNDLE_URL` | 本组件自己的 bundle，例如 `http://infra-authz-2-0-0:8223/authz/bundle`：管理 API 按它判 `infra.authz.admin`。必填。所有组件都指向同一个 URL；本组件换版本时各处一起改。 |
| `IAM_JWKS_URL` | 本地验签用户 token 用的 JWKS 地址，例如 `http://infra-iam-casdoor-2-0-0:8200/.well-known/jwks.json`。必填。 |
| `PERMISSION_CATALOG` | 权限键登记表的文本：制表符分隔，一行一个键，列为 `key`、`title`、`type`、`owner_component`、`deprecated`（最后一列可空或省略）；空行、`#` 开头的行与表头跳过。写成 `file://<登记表路径>`，值永远就是文件本身。必填，没有默认值。某一行少于四列或 key 为空时整次同步失败，ERROR 日志 `同步权限目录失败` 里带行号；表里保持原有内容。 |
| `ACCESS_TOKEN_TTL_SECONDS` | IAM 适配层签发的应用 access token 有效期；默认 `600`。`stale_since` 覆盖两倍这个时长之内的变化，所以必须等于 IAM 适配层的 token 有效期。 |
| `DEFAULT_ORG_ID` | `ResolveClaims` 对所有人返回的组织 ID；默认 `1`（一个部署一个组织）。 |
| `BOOTSTRAP_ADMIN_SUB` | 第一个管理员的 `sub`，每次启动时授予 `authz_admin`（幂等）；默认为空（不授予任何人）。BrickEnterprise 项目里写 `${INFRA_AUTHZ_BOOTSTRAP_ADMIN_SUB:-}`。 |

## 契约索引

- `contracts/infra/authz/v1/authz.proto` —— gRPC `infra.authz.v1.AuthzService`：`ResolveClaims`（sub → 角色、部门路径、组织 ID；IAM 适配层每次登录与刷新都调，绝不缓存）、`GetBundle`（与 REST 同一份 bundle）、`BatchGetRoles`（按 code 批量读角色；不存在的 code 省略，不报错）。Go 包是独立模块 `github.com/brickKit/infra-authz/gen/infra/authz`，`infra/iam-casdoor` import 它。
- `contracts/authz.openapi.yaml` —— REST 用裸路径，不在 `/infra/authz` 下：`GET /authz/bundle`（公开，只在内网可达，不是网关路由；`ETag` 与 `If-None-Match` → `304`）、`GET /api/me/permissions`（任何已登录用户；调用者自己的键，取自 token 的 `sub`），以及要 `infra.authz.admin` 的：`GET`/`POST /api/admin/roles`、`GET`/`DELETE /api/admin/roles/{code}`、`POST /api/admin/roles/{code}/permissions`、`DELETE /api/admin/roles/{code}/permissions/{key}`、`GET`/`POST /api/admin/users/{sub}/roles`、`DELETE /api/admin/users/{sub}/roles/{code}`、`POST /api/admin/users/{sub}/permissions`（经专属角色）、`POST /api/admin/users/{sub}/revoke`（撤销全部角色）、`GET`/`POST /api/admin/departments`、`POST /api/admin/users/{sub}/department`。
- `contracts/events/authz.events.json` —— 声明了 `infra.authz.role.changed.v1` 与 `infra.authz.user_role.changed.v1` 两个只供审计的旁路事件。本版本还没有发出它们，也没有消费者。bundle 从不依赖事件：变化靠轮询到达各组件。不消费任何事件。
- `assembly.yaml` —— 本项目的元数据：权限键 `infra.authz.admin`、菜单项、网关路由 `/api/me/permissions` 与 `/api/admin/**`、schema 与角色、`data_scopes: none`。

## 外壳声明

不是外壳。可以由 Go 外壳托管（BrickEnterprise 项目里是 `be/go-infra`），也可以单独运行；两种方式代码相同。进外壳后 `AUTHZ_BUNDLE_URL` 仍用本组件自己的服务名。
