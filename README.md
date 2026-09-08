# infra-authz · 权限账房

权限键册、角色模型（纯并集，无 Deny）、`GET /authz/bundle` 策略下发、登录期 claims 计算——设计书第 14 章称本组件为权限体系的**账房**：它不在任何用户请求的判权限热路径上（那是各组件 `be-sdk` 的进程内 map 查找），只负责把"角色能做什么"这份策略算出来、发出去。这是权限体系里**唯一需要自己持久化状态**的组件。

## 它能做什么

- `GET /authz/bundle`：把 `role -> [permission keys]` 与一个有界的 `stale_since` 列表打包成一份 JSON，供全部组件的 `be-sdk` 每 15 秒条件轮询（`ETag`，未变化返回 `304`）
- 角色模型的管理界面后端：建/删角色、给角色勾权限键、给人授/撤角色（可带到期时间）、给人单独加一个权限（自动走专属角色 `u:<sub>`）、踢人（撤销全部角色）
- `ResolveClaims`：登录/刷新时供 `infra-iam-casdoor` 查询 `sub -> roles[]/dept_path/org_id`，绝不缓存
- 阶段三的极简部门表（`departments`/`user_departments`）：只为给出 `dept_path` 这一个字符串，阶段五由 `mdm-org` 接管
- 权限键册的宿主：`be-ops` 产出 9 经 `config.permissionCatalog` 灌入，本组件 upsert 进 `permissions` 表

## 需要哪些基础资源

| 资源 | 形态 | 为什么需要 | 怎么起 |
|---|---|---|---|
| PostgreSQL 16 | **A**（`kind: database`） | 数据持久化，独占 schema `infra_authz`——本组件是权限体系里唯一持久化状态的组件 | 装配仓库根目录 `make up` |
| NATS 2.10 | **A**（`kind: mq`） | 发布 `infra.authz.role.changed.v1`/`infra.authz.user_role.changed.v1` 两条旁路审计事件（仅供 `infra-audit`，不驱动任何下发逻辑） | 同上 |

⚠️ 本组件**不需要** Traefik/Casdoor 就能单独跑起来——它自己也走 JWT 本地验签（`iamJwksUrl`），不对 IAM 建依赖边（§6.12）。它也**不依赖任何其他组件**：唯一的弱依赖 `mdm/org` 要到阶段五才存在，`dependencies.components` 现在是空数组。

## 怎么起来

```bash
# 装配仓库根目录
make up                        # 起 PostgreSQL/NATS 等默认基础资源
cd components/infra/authz
go build -o build/migrate ./backend/cmd/migrate
PG_SCHEMA=infra_authz DATABASE_HOST=localhost DATABASE_PORT=5432 \
  DATABASE_USER=postgres DATABASE_PASSWORD=<.env 里的 POSTGRES_PASSWORD> DATABASE_NAME=brickkit_db \
  ./build/migrate up
go run ./backend/cmd/server     # 单独跑：besdk.RunStandalone 读 component.yaml 的端口
```

或者用平台：`brickkit up`（装配仓库根目录，`components/infra/authz` 已登记为 submodule 且在 `brickkit.yaml` 里之后）。

## 怎么用

```bash
# 策略下发（内网调用，不经网关）
curl http://localhost:8223/authz/bundle
# {"roles":{"authz_admin":["infra.authz.admin"]},"stale_since":{}}

# 建一个角色
curl -X POST http://localhost:8223/api/admin/roles \
  -H 'Content-Type: application/json' \
  -d '{"code":"sales_manager","name":"销售经理"}'

# 给角色勾一个权限键（权限键必须已经在 permissions 表里，见「配置项」）
curl -X POST http://localhost:8223/api/admin/roles/sales_manager/permissions \
  -H 'Content-Type: application/json' -d '{"permission_key":"infra.authz.admin"}'

# 给某个人授这个角色
curl -X POST http://localhost:8223/api/admin/users/u_zhangsan/roles \
  -H 'Content-Type: application/json' -d '{"role_code":"sales_manager"}'

# gRPC：登录期 claims 计算（infra-iam-casdoor 的调用方式）
grpcurl -plaintext -d '{"sub":"u_zhangsan"}' localhost:9223 infra.authz.v1.AuthzService/ResolveClaims
```

## 配置项

| 配置键 | 默认值 | 说明 |
|---|---|---|
| `pgSchema` | `infra_authz` | 本组件的 PG schema |
| `iamJwksUrl` | 无默认值 | JWT 本地验签的公钥来源——本组件自己的管理 API 也要验 JWT（见「自我鉴权」） |
| `authzBundleUrl` | 无默认值 | ⚠️ 指向自己——本组件的管理 API 用 `besdk.RequirePermission` 保护，需要轮询自己下发的 bundle |
| `otelBaseUrl` | `""`（Blackhole Exporter） | OTel collector 地址 |
| `permissionCatalog` | `""` | `be-ops` 产出 9 灌入的权限键册，见下方「permissionCatalog 编码格式」 |
| `accessTokenTtlSeconds` | `600`（10 分钟） | `stale_since` 窗口 = 2× 这个值，必须与 `infra-iam-casdoor` 签发 access token 的 TTL 一致 |
| `defaultOrgId` | `"1"` | 阶段三只有一个默认法人/组织，`ResolveClaims` 对所有用户返回同一个值 |
| `bootstrapAdminSub` | `""` | 首个管理员的 sub，见下方「自举」 |

### permissionCatalog 编码格式（阶段三 Task 4 设计决策）

条目之间用逗号分隔，条目内部 4 个字段用竖线分隔：

```
erp.sales.view|查看销售订单|page|erp/sales,mdm.customer.view|查看客户主数据|page|mdm/customer
```

选 `|`/`,` 而不是 JSON：权限键（`{domain}.{aggregate}.{action}`）与组件 ID（`{domain}/{name}`）都不可能含有这两个符号，中文标题也几乎不会，比 JSON 更省字节；且平台把 YAML 数组渲染成 `[a b c]` 这条雷（导读第 7 条）天然不适用逗号分隔字符串。

### 自举：第一个管理员怎么来

`infra.authz.admin` 权限键与 `authz_admin` 角色由迁移直接种下（`003_seed_bootstrap_admin_role.up.sql`），但**授予给谁**是客户特定的——`Start()` 读 `bootstrapAdminSub`，非空时幂等地把 `authz_admin` 授给这个 sub。留空表示先不自举任何人（客户可能选择完全手工建）。

### 自我鉴权：管理 API 也吃自己下发的 bundle

`/api/admin/**` 用与全平台其余 61 个组件完全相同的机制保护（`besdk.RequirePermission` 查内存 bundle map），本组件对自己的 `authzBundleUrl` 配的是自己的地址——是一个刻意的自我引用，不是特例。`/authz/bundle` 本身永远是 `besdk.Public`：它是判权限的数据来源，不能靠它自己判权限。

## 参考实现

| 项目 | 版本/commit | 看的模块 | 借鉴了什么 | 许可证（已复核） | 用法 |
|---|---|---|---|---|---|
| Open Policy Agent | v0.68（文档） | Bundle API（`ETag` 条件拉取、fail-static 降级） | 本组件的下发形态整个来自它：策略下发到本地、决策在内存；拉不到就用旧的继续跑 | Apache-2.0 | 借鉴逻辑 |
| Kubernetes RBAC | 文档 | `rbac/v1` 的 Role/RoleBinding | 纯并集、无 Deny 的立场与公开理由（可推理性） | Apache-2.0 | 借鉴逻辑 |
| Salesforce | — | Profile/Permission Set | "基线 + 可叠加权限集"这个分层；以及它的 Sharing Table 重算代价——正是我们把数据权限放到版本里的直接理由 | 闭源 | 借鉴实际应用 |

**明确没有参考的**：Zanzibar/SpiceDB/OpenFGA 的关系元组模型——它解决的是"每条资源有自己的 ACL"，ERP 的可见性是"按组织结构成片划分"，用关系元组表达等于给每条单据存一行 ACL；且它的性能靠几万台机器换来，对"客户本地一台电脑"的形态不成立（设计书 §14.1.4）。

## 边界与禁令

- **本组件不做数据权限**——`data_scopes: none`。能进管理界面的人（`infra.authz.admin`）就能看全部角色/权限数据，这是功能权限的事
- **不做 Deny（显式拒绝）**，只做并集。"除了 X 都能做"的正确表达是给一个不含 X 的角色，不是加一条 Deny 规则
- **策略下发不走事件总线**——bundle 轮询是无状态、幂等、天然收敛的；两条事件（`role.changed`/`user_role.changed`）仅供 `infra-audit` 落审计，不驱动任何下发逻辑
- **角色内容变更不写 `role_changes`、不产生 `stale_since`**——那靠 bundle 的 `roles` 字段直接刷新；只有"人的角色变了"（授予/撤销/踢人/到期）才需要让已签发的 token 变 stale
- `departments`/`user_departments` 是阶段三的临时表，阶段五 `mdm-org` 上线后退役，不要在这上面投入超出"能用"的设计
