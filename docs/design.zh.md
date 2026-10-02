[English](design.md) · [中文](design.zh.md)

# infra/authz 设计

只写结论，给要改本组件设计的人看。怎么用：`BRICKKIT.zh.md`；代码怎么组织：`AGENTS.zh.md`。

## 边界

本组件是权限体系的账房：权限键目录、作为权限键纯并集的角色、谁持有哪个角色，以及由它们算出的策略 bundle。它是权限体系里唯一保存状态的部分；判定本身发生在每个组件的进程里，对着内存里的 bundle 副本做。

| 不在这里 | 归谁 | 为什么 |
|---|---|---|
| 身份、密码、登录、OIDC、签发 token | Casdoor + `infra/iam-casdoor` | 本组件只认 `sub` 字符串。这样换身份提供方时，角色数据一行都不用迁 |
| 每次请求的权限判定 | 每个组件里的 SDK | 每次请求都过一个中心判定点，就是 Zanzibar 式的服务；它不适合"一个客户、一台机器"，也会把本组件放到每个请求的路径上 |
| 行级数据范围 | 各组件的 `assembly.yaml` 与代码 | 数据范围随组件版本上线，不在这里配置 |
| 组织主数据（部门、岗位、汇报线） | 组织主数据组件 | 这里只需要部门路径这一个字符串；部门表是那个组件出现之前的权宜之计 |
| 菜单 | 各组件的 `assembly.yaml`，由装配工具汇总 | 没有中心菜单表 |
| 审计日志 | 审计组件 | 本组件发事件，审计组件落库 |

## 拥有的数据

| 表 | 分区 | 说明 |
|---|---|---|
| `permissions` | 否 | `key` 主键；`title`、`type`、`owner_component`、`deprecated`。登记表的镜像，每次启动 upsert；行从不删除 |
| `roles` | 否 | `code` 是自然主键（bundle 按它组织）；`is_system` 标记专属角色 `u:<sub>` 与自举角色 `authz_admin` |
| `role_permissions` | 否 | `(role_code, permission_key)`；两个外键都 `ON DELETE CASCADE` |
| `user_roles` | 否 | `(sub, role_code)`；`expires_at` 为空表示永不过期。唯一随用户数增长的表；不进 bundle |
| `role_changes` | 按 `changed_at` 月分区 | `granted` / `revoked` / `kicked`；`stale_since` 的来源。与 `user_roles` 的变化在同一事务里写 |
| `departments`、`user_departments` | 否 | 部门树（`dept_path` 含部门自己的 ID，例如 `/1/12/`）与 sub → 部门 |
| `event_outbox` | 按 `created_at` 周分区 | 后台循环从这里推送；没有 `event_inbox`（不消费任何事件） |

终态：`role_changes` 的行写入即终态；到期的 `user_roles` 行留在表里（谁在什么时候有过什么），但不再生效。迁移 `003` 建好权限键 `infra.authz.admin`、角色 `authz_admin` 以及两者的关联；授给谁因部署而异，在启动时按 `BOOTSTRAP_ADMIN_SUB` 授予，因为迁移不应依赖运行期配置。

**部门路径的含义，以及空路径的含义。** 一个部门的 `dept_path` 是含它自己在内的祖先链，形如 `/<id>/…/`；顶层部门是 `/<id>/`。`ResolveClaims` 返回此人所在那一个部门的路径，没有部门时返回空串——这是合法状态（新账号一开始就是这样）。空串的意思是"没有部门"，绝不是"根"：SDK 自 v0.5.0 起把它换成一个不匹配任何真实路径的哨兵，于是每个数据范围的 `org` 维都一行不中，`owner OR org` 判据只剩此人自己的行。按字面用，空前缀会匹配一切（`LIKE '' || '%'`、`strings.HasPrefix(x, "")`），没分部门的人就看得到全部行：这是 fail-open 的安全默认值。所以"看全公司"是身份，不是特权：把这个人分到根部门，根部门的路径是其它所有路径的前缀。`/` 是整棵树（同时有多棵顶层树时）的显式标记；本组件从不签发它，一棵树用不到，部门表也只是权宜之计。签出去的 claim 形状没变，所以不改契约、不需要重新登录：早先签发的空路径 token，在消费方用上新 SDK 时只是失去 `org` 维的那些行。

**目录直接来自登记表本身。** `PERMISSION_CATALOG` 是 `registry/permissions.tsv` 的内容，写成 `file://registry/permissions.tsv`。备选方案——由装配工具生成一份目录文件——多出一个"加了键之后记得重新生成"的步骤，漏一次，新键就悄悄永远进不了表。直接读登记表没有这个步骤：追加一个键之后，下一次 `brickkit up` 重建组件，启动时就同步了。每行制表符分隔，至少四列；表头、空行与 `#` 行跳过；某行列数不足或 key 为空时整次同步失败，并给出行号。`deprecated` 非空的行与其它行一样同步，`deprecated` 也一起同步：某个角色还持有的退役键必须仍能解析到。

## 契约面

gRPC `infra.authz.v1.AuthzService`：

| rpc | 类型 | 说明 |
|---|---|---|
| `ResolveClaims` | 读 | 给 `infra/iam-casdoor`：sub → 角色、部门路径、组织 ID（`DEFAULT_ORG_ID`，一个部署一个）。每次登录、每次刷新都调，绝不缓存：应用 token 按它的结果签发，所以一个 stale 的 token 刷新一次就带上当前角色 |
| `GetBundle` | 读 | 与 REST 同一份 bundle，给更愿意走 gRPC 的调用方 |
| `BatchGetRoles` | 读 | 一次按一批 code 读角色；不存在的 code 省略；别的错误照常返回 |

REST 用裸路径（不在 `/infra/authz` 下）：`/api/me/permissions` 与 `/api/admin/**` 是全平台共用的路径，与由哪个组件提供无关。

- `GET /authz/bundle` —— 公开，只在内网：它不在 `edge_routes` 里，网关路由表就不会暴露它。它是所有权限判定依赖的数据，不能再用权限判定保护它自己。每次请求现算（角色及其权限键是几百行；`stale_since` 只读一个有界窗口），`ETag` 是响应体的 SHA-256；`If-None-Match` 与之相等 → `304`。
- `GET /api/me/permissions` —— `besdk.Authenticated`：调用者全部权限键的并集，直接查数据库而不是查本组件自己的 bundle（"我现在能做什么"没有 15 秒的延迟）。`sub` 只取自已验签的 token。
- `/api/admin/**` —— 每条路由都要 `infra.authz.admin`：角色（列表不含专属角色、新建、查看、删除；授予 / 撤销一个键）、一个人的角色（列出当前有效的、带可选到期时间授予、撤销）、"给一个人单独加一个键"（确保专属角色 `u:<sub>` 存在、加上这个键、授予这个角色；每一步都幂等，重试会补完半途的调用）、`revoke`（撤销一个人的全部角色，写一行 `kicked`）、部门（列出、新建）与一个人的部门。

写操作靠构造本身幂等（upsert 与 delete），不靠幂等键：同一个角色、同一个到期时间授两次什么都不变，也不写 `role_changes`；撤销本来就没有的分配什么都不写。没有状态端点：没有组件在自己的事务里写这里。

**stale token。** bundle 的 `stale_since` 把一个 `sub` 映射到两倍 access token 有效期（`ACCESS_TOKEN_TTL_SECONDS`，必须等于 IAM 适配层的设置）之内此人角色最近一次变化的时间：来自 `role_changes` 的 `granted`、`revoked`、`kicked`，以及落在窗口内且已经过去的 `user_roles.expires_at`。签发早于这个时间的 token 得到 `401 token_stale`，前端刷新，`ResolveClaims` 返回当前角色。更早的变化不需要记录：在它之前签发的 token 早已过期。改一个角色持有哪些键不会让任何人变 stale：token 里只有角色、没有键，新键随下一次轮询到达。改一个人的部门也不会：新路径在下一次刷新时到达，最多晚一个 token 有效期。

## 事件

`contracts/events/authz.events.json` 里声明了：`infra.authz.role.changed.v1`（角色新建、删除或其权限键变化）与 `infra.authz.user_role.changed.v1`（一个人的角色被授予、撤销、到期、踢出）。两者都只供审计的旁路事件：bundle 从不依赖它们，因为轮询无状态、幂等、自然收敛，而靠事件下发就要求每个组件消费、落库、处理乱序与重放。

本版本两个事件都还没有写进 Outbox；Outbox 表与后台循环都在，这两个 subject 目前也没有消费者。见未决问题。

消费：无。

## 依赖

无。预期中可能有、实际没有的：

| 不是依赖 | 为什么 |
|---|---|
| `infra/iam-casdoor` | 调用方向相反：IAM 适配层调这里的 `ResolveClaims`。本组件只认 `sub` 字符串 |
| 所有业务组件 | 它们经 `AUTHZ_BUNDLE_URL` 找到本组件，是配置不是边。每个组件都连一条边只会白白把启动顺序绑在一起；fail-static 的轮询让顺序无关紧要 |
| 审计组件 | 走事件，不走调用 |
| 组织主数据组件 | 它还不存在；部门表先顶着。它出现后变成可选依赖或事件来源 |
| `infra/authz` 自己 | 管理 API 按 `AUTHZ_BUNDLE_URL` 上的 bundle 判 `infra.authz.admin`，而这个地址指向本组件：与别处同一套判定，不是特例 |

## 在同步调用图里的位置

不在图里。没有组件与本组件之间有同步边。唯一真实发生的调用 `infra/iam-casdoor` → `ResolveClaims` 在登录与刷新路径上，不在业务请求路径上。每个组件每 15 秒经 HTTP 轮询一次 bundle；那是配置加后台循环，不是调用图里的边。与三枢纽、与"CRM 与 ERP 之间没有同步边"都无关。

## 分区与归档

| 数据 | 热 | 归档 |
|---|---|---|
| `permissions`、`roles`、`role_permissions` | 一直热 | 从不 |
| `user_roles` | 一直热 | 从不；到期的行留着，回答"他当时有什么" |
| `role_changes` | 最近两个 token 有效期 | 设想超过 7 天归档到 `infra_authz_archive`；还没有归档任务，月分区只是累积（见未决问题） |
| `event_outbox` | 周分区 | 随分区向前滚动 |

`role_changes` 只有最近两个 token 有效期参与 `stale_since`，所以无论表里有多少变化，列表都很短（个位数到几十条），bundle 也很小。组件在启动时与此后每 24 小时，提前建好 `event_outbox` 四周的分区和 `role_changes` 三个月的分区。

## 数据范围

无（`data_scopes: none`）。能打开角色管理页面的人（`infra.authz.admin`）看到全部角色、授权与部门：这是功能权限。按部门限制它，就是给权限数据本身加数据范围——没人需要，还会让"谁能授予什么"依赖组织树。

但它是其它组件 `org` 维所读 `dept_path` 的来源（见"拥有的数据"）：没有部门的人在那里只看得到自己的行，看全公司就是分到根部门。

## 参考实现

| 项目 | 版本 | 看的模块 | 借鉴了什么 | 许可证 | 用法 |
|---|---|---|---|---|---|
| Open Policy Agent | v0.68（文档） | Bundle API：`ETag` 条件拉取、拉取失败时 fail-static | 整个下发模型：策略下发到每个进程，判定在内存里做，拉取失败沿用上一份 | Apache-2.0 | 借鉴逻辑 |
| Kubernetes RBAC | 文档 | `rbac/v1` Role / RoleBinding | 纯并集、没有拒绝，及其公开理由（规则容易推理） | Apache-2.0 | 借鉴逻辑 |
| Casbin | 文档 | RBAC with domains | 只看了模型分层；不引入：这里的模型简单得多，引进库只多一层间接 | Apache-2.0 | 借鉴逻辑 |
| Salesforce | — | Profile / Permission Set | "基线 + 可叠加的权限集"；以及它 Sharing Table 重算的代价——数据范围随组件版本走的直接理由 | 闭源 | 借鉴实际应用 |
| AWS IAM | — | 策略求值、最终一致性 | 拒绝 / 允许求值顺序作为反例；"策略变更几秒内生效"作为 15 秒轮询的标尺 | 闭源 | 借鉴实际应用 |

**刻意避开的**：Zanzibar / SpiceDB / OpenFGA 的关系元组——它们建模的是"每个资源有自己的 ACL"（文档共享），而 ERP 的可见性是"按组织成片划分"；用元组表达就是每张单据一行 ACL，而且它们的性能靠很多台机器。SAP 把功能权限与数据权限混在一个权限对象里（两者的变化频率不同：每天 vs 按制度）。把全部权限键塞进 JWT（管理员的全集撑爆请求头：登录成功，随后每个请求都 `431`）。Odoo 由 ORM 注入的 `ir.rule` domain 表达式（这里没有 ORM；运行期字符串 AI 既读不懂也测不了）。

没有槽位族：常见的五档数据范围在成熟 ERP 里一致；不同的是一个组件按哪些维度划分，那在各组件的 `assembly.yaml` 里声明。

## 未决问题

| 问题 | 目前的答案 |
|---|---|
| 声明了的两个审计事件要不要发出，`version` 用什么（角色与授权没有版本列）？ | 本版本不发，也没有消费者；版本语义是契约决定，等审计组件设计时一起定 |
| 部门表怎么迁到组织主数据组件，两份 `dept_path` 共存期间怎么保持一致？ | 等那个组件设计时再定 |
| 真实客户的角色集下 bundle 有多大？ | 估计几十 KB；超过约 1 MB 就按组件前缀切片下发 |
| `role_changes`（这里保留 7 天窗口）与审计组件的长期日志是否重叠？ | 等审计组件出现再定；在那之前不写归档任务，分区累积（每次变化几行） |
| `scripts/seed.sh` 能不能改走管理 API 给种子超级用户授权，而不是直接写库？ | 只有 `BOOTSTRAP_ADMIN_SUB` 已经是这个用户的 `sub` 时才行——这要求先建好 IAM 种子用户、把它的 `sub` 写进 `.env`、在灌种子之前重启本组件。本地开发时 `BOOTSTRAP_ADMIN_SUB` 留空，所以第 ① 步继续直接写第一个角色；之后每一步都走管理 API |
| 管理 API 能像删别的角色一样删掉 `authz_admin` 或某个专属角色 | 目前允许；给 `is_system` 角色加保护是行为变化，跟前端的角色页面一起定 |
| `MyPermissions` 跳过读不到的角色（两次查询之间被删了），别的读取错误也一并跳过，返回部分集合 | 接受：这个结果只决定前端显示哪些按钮，每个操作在服务端还会再判一次 |
