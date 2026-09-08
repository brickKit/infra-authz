# infra-authz · AI 助手导读

## 身份证

| 项 | 值 |
|---|---|
| 组件 ID | `infra/authz` |
| 仓库名 | `infra-authz` |
| 端口 | HTTP `8223` / gRPC `9223`（`registry/ports.tsv`，装配仓库根目录那份） |
| schema / role | `infra_authz` / `infra_authz_rw`（归档 schema `infra_authz_archive`，本组件目前不归档任何数据——`role_changes` 只有 7 天窗口，量级太小暂不需要） |
| 语言 / 框架 | Go：Gin + `database/sql` + `pgx/v5/stdlib` + `golang-migrate` |
| 合并部署时进 | 外壳三 `go-infra` |
| 装配角色 | `default` |
| 设计真相源 | 装配仓库 `docs/design/infra-authz.md`——本文件与它冲突时，以那份为准，回来改这里 |

## 边界

**归我：** 权限键册的宿主、角色模型（纯并集，无 Deny）、`GET /authz/bundle` 策略下发、`stale_since` 有界列表、登录期 `ResolveClaims`、阶段三极简部门表（只为给出 `dept_path`）。设计书第 14 章称本组件为权限体系的**账房**——不在任何用户请求的判权限热路径上，只把策略算出来、发出去。

**不归我：**

| 什么 | 归谁 | 为什么 |
|---|---|---|
| 用户身份、密码、登录、OIDC 流 | Casdoor 官方镜像 + `infra-iam-casdoor` | 我只认 `sub`。这条切分让 `slot:iam` 换 Keycloak 时角色数据一行都不用迁 |
| **单次鉴权判定** | 各组件的 `be-sdk`（进程内 map） | 我不在请求热路径上。做成中心 PDP 就是 Zanzibar，对"客户本地一台电脑"不成立 |
| **数据权限规则** | 各组件的 `assembly.yaml` + 代码 | 数据权限随版本上线，不在我这里配。本组件自己 `data_scopes: none` |
| 组织架构主数据（部门、岗位、汇报线） | `mdm-org`（阶段五） | 我只借用"部门路径"这一个字符串，`departments`/`user_departments` 是阶段三临时表 |
| 菜单树 | 各组件 `assembly.yaml` 的 `menus`，`be-ops` 生成期聚合 | 没有中心菜单表 |
| 审计日志 | `infra-audit` | 我发事件，它落库 |

## 契约面与事件

**gRPC `infra.authz.v1.AuthzService`：** `BatchGetRoles`（读，§3.8 强制的 batchGet）、`ResolveClaims`（读，给 `infra-iam-casdoor`：`sub -> roles[]/dept_path/org_id`，**登录与刷新时各调一次，绝不缓存**）、`GetBundle`（读，gRPC 版策略下发）。

**REST：** ⚠️ 路径**不走** `/{domain}/{name}/**` 前缀（与其余组件不同）——`GET /authz/bundle`（内网调用，不进 `edge_routes`，不经网关）、`GET /api/me/permissions`（全平台通用的"我的权限"端点）、`/api/admin/roles/**`、`/api/admin/users/{sub}/**`、`/api/admin/departments`。全部权限键统一是 `infra.authz.admin`（`/api/me/permissions` 语义上"仅需登录不需要具体键"，见下方「已知缺口」）。

**发布事件：** `infra.authz.role.changed.v1`、`infra.authz.user_role.changed.v1`——两条都是旁路事件，仅供 `infra-audit` 落审计，**不驱动任何下发逻辑**（策略下发只走 bundle 轮询）。

**消费事件：** 无（阶段三）。`mdm.org.department.changed.v1` 是阶段五才会有的消费方，现在 `dependencies.components` 是空数组。

## 依赖与「为什么不依赖某某」

`dependencies.components` 永远是空数组（阶段三）。

- **不依赖 `infra-iam-casdoor`**：方向是反的——是 `iam` 调我算 claims，不是我调它。我只认 `sub` 这个字符串，这条切分是 `slot:iam` 可替换的物理前提。
- **不依赖任何业务组件**：反过来也一样，62 个组件对我不声明依赖，我的地址走各组件 `configSchema` 的 `authzBundleUrl`（同 `iamJwksUrl` 先例）。61 条依赖边既没必要，也会把启动顺序绑死；fail-static 降级让顺序无关紧要。
- **不依赖 `infra-audit`**：走事件，不同步调。
- **`mdm/org` 是弱依赖但现在不写依赖边**：它阶段五才会建仓库——没有已写好的仓库就不建边（"8 个非组件仓库判据"同一条精神），阶段五上线时补。

## 这个组件特有的坑

| 不许 | 症状 | 出处 |
|---|---|---|
| `ComputeBundle`/`loadRolesInto` 按 `is_system` 过滤角色 | 持有专属角色 `u:<sub>` 的用户在所有业务组件里静默失权，完全没有任何报错——他的 JWT `roles[]` 里带着 `u:zhangsan`，bundle 里找不到这个 key，`be-sdk` 展开出来就是空集 | `docs/手册.md` §6、`bundle.go` 顶部注释 |
| 给"角色内容变更"（勾/取消一个权限键）写 `role_changes` 或计入 `stale_since` | 不是 bug，是浪费——角色内容变更本来就靠 bundle 的 `roles` 字段在下一次轮询直接刷新，不需要让任何已签发的 token 失效。真正需要 `stale_since` 的只有"人的角色变了"（授予/撤销/踢人/到期） | `roles.go` 的 `GrantRolePermission`/`RevokeRolePermission` 注释、设计书 §14.1.6 |
| 给"到期"（`expired`）单独写一条 `role_changes` 或起一个后台扫描任务 | 不需要——到期是纯粹的时间流逝，`loadStaleSinceInto` 直接从 `user_roles.expires_at` 落在窗口内、且已经过去的行推导。加一个扫描任务是多余的复杂度 | `002_create_outbox_and_role_changes.up.sql` 注释、`bundle.go` |
| `GrantRolePermission`/`role_permissions` 的插入用"先 SELECT 判断权限键存不存在，查不到再报错" | 用 FK 约束自然拒绝就够了（`mapConstraintErr` 把 `23503` 翻成 `ErrNotFound`），多一次查询是浪费；且有并发窗口——两条语句之间权限键可能被删掉 | `roles.go` |
| `SyncPermissionCatalog` 删除本次目录里没有出现的 key | 违反"只增不改"——已发布的权限键必须永远保留，废弃走人工 `deprecated` 墓碑列（`registry/permissions.tsv` 的同一条判据在这里的落地） | `permissions.go` |
| 用 `array_agg` 把 `role_permissions.permission_key` 聚合后直接 `Scan` 进 `[]string` | `pgx` 的 `database/sql` 通用接口不会自动解 PostgreSQL 的 `text[]`，会报 `unsupported Scan`——真机测试实测踩出来的 | `bundle.go` 的 `loadRolesInto` 注释 |
| 给 `bootstrapAdminSub`/`permissionCatalog` 为空时报错或拒绝启动 | 两者都是合法的启动态（还没配置第一个管理员、还没有任何组件声明权限键），`Start()` 应该跳过而不是失败 | `service.go` 的 `EnsureBootstrapAdmin`/`SyncPermissionCatalog` |

## 已知缺口（阶段三 Task 4 实现时发现，留给后续任务）

- **`be-sdk` 目前只有 `Public`/具体权限键两档判据，没有"已登录但不需要具体权限键"这一档**——`GET /api/me/permissions` 语义上就是这一档（任何登录用户都该能查自己的权限，不需要额外的权限键）。这是 Task 5 该补的一个真实缺口，本组件的 `myPermissionsHandler` 目前用一个临时 debug header（`X-Authz-Debug-Sub`）取调用者身份，**不是安全机制**，上线前必须换成从已验签 JWT 的 claims 取 `sub`。
- **`/api/admin/**` 目前也标 `besdk.Public`**——真实权限键 `infra.authz.admin` 已经在 `assembly.yaml` 声明好，等 Task 5 把 `be-sdk` 的判定换成真实 bundle 查找后，本组件（连同其余五个组件）一起换成真实键。本组件的特殊之处是它自吃自己下发的 bundle（`authzBundleUrl` 指向自己）——这是刻意的自我引用，不是需要绕开的特例。

## 改代码前的自查

1. **我是不是在 `ComputeBundle`/`loadRolesInto` 里按 `is_system` 过滤？** 停下——那会让持有专属角色的用户静默失权，参见上表第一条。
2. **我是不是在给"角色内容变更"写 `role_changes`？** 停下——只有"人的角色变了"才需要，角色内容变更靠 bundle 直接刷新。
3. **我是不是在给"到期"单独建一个后台扫描任务？** 停下——`user_roles.expires_at` 已经足够 `loadStaleSinceInto` 现算，不需要额外的任务。
4. **我改的 `SyncPermissionCatalog`/权限键相关代码，会不会删除已发布的 key？** 停下——只增不改是硬约束，废弃走人工墓碑列。
5. **我新加的角色/权限键操作，是不是也顺手给了 `role_changes` 记账？** 检查它是不是真的属于"人的角色变了"这一类；不是的话不要记账。
6. **这个改动会不会让 `contracts/authz.proto` 出现破坏性变更？** 全部 62 个组件的 `be-sdk` 都轮询本组件的 bundle，是全系统扇出最广的一份契约，只能向后兼容地追加。
7. **我是不是在往 `dependencies.components` 加一条边（尤其是 `mdm/org`）？** 停下——它阶段五才存在，现在加边会让 `brickkit up` 找不到这个组件的 Manifest。
