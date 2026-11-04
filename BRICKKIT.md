# infra/authz

## 组件定位

授权成员，做三件事：
- 接收每个组件启动时提交的定义（资源、维度、字段、操作）；
- 保存安全记录，只在生效点改变它们；记录有管理职责单元与持有、角色修订、授予；
- 每个组件核验视图时，在主库上按已提交的记录重新计算它的视图并回答。

授予不能超出授出者的管理上限：生效点现场做包含证明（安全 07），不复用旧的见证。最后一个授权管理员不能被移除。每个生效的变更都推进安全修订号，并与审计记录同一事务写入。

本组件的用户面也受授权保护，它向自己核验自己的视图，与其他组件一样。

账号状态来自身份成员（安全 03 的内部来源）：本组件以带水位的投影保存它（补取、按 ID 批量读取与快照都是身份成员系统面上的标准方法），视图里每个主体带账号是否停用与安全状态版本（入口组件据此判令牌陈旧）。身份来源的水位超过 `AUTHZ_SOURCE_HIGH`（`D_src_high`，起始 1 分钟）时，视图只为普通读取续发，高风险操作在它的有效期过后关闭；超过 `AUTHZ_SOURCE_READ`（`D_src_read`，起始 10 分钟）、或投影还没对齐时，视图关闭，受保护的请求答可重试的 `AUTHORIZATION_VIEW_EXPIRED`。单个账号的状态无法证明时（它的事件被隔离），这个主体不进视图，其他主体照常。部署第一次启动、投影对齐之前，全部视图关闭。

记录有完整的生命周期（安全 08）：待生效的到点生效，来源收紧后视图立即缩小（授予只在治理单元逐级到根的当前上限之内有效），之后由闭包作业把记录记为结束或暂停；持有者可以放弃自己的授予与管理持有资格（`POST /api/authz/relinquishments`）。3.0.17 还没有做的，用到时答“能力不支持”（`CAPABILITY_UNSUPPORTED`）：
- 确认与受保护操作；
- 严格路径（A、B 档）；
- 成员切换；
- 共享、委托与扮演；
- 任职关联的授予；
- 包含证明里沿一个维度拆分；
- `relation` 与 `record` 维度。

安装认领做了简化：配置里的主体成为第一个授权管理员。

## 部署前准备

- 数据库：PostgreSQL 16 及以上；schema `infra_authz`，属主角色 `infra_authz_owner`（只供迁移）与运行角色 `infra_authz_rw`，名字来自装配项目的注册表。三者由部署方在第一次启动前建好（be-assembly-standard 的 `make db-init` 按装配进项目的组件配置生成并执行）；表由本组件的迁移建。
- `AUTHZ_INSTANCE`：安装时生成一个 UUID，随部署的运行档案保存，以后不再改变。本组件发现库里记的实例与配置不同时，拒绝启动。
- `AUTHZ_REGISTRY`（通常写成 `file://`，或用 `AUTHZ_REGISTRY_FILE`）：
  - 资源类型与权限键的属主，由装配从注册表生成；
  - 格式是 TSV，三列为 `kind`、`key`、`owner_component`，`kind` 取 `resource_type` 或 `permission`；已退役的权限键多第四列，写退役日期：退役的键不再给任何访问（授予照旧，视图里它的段为空）；
  - 本组件约 30 秒重读一次这个文件，退役在那之后的下一次核验生效；
  - 本组件自己的键也要在里面。
- `AUTHZ_BOOTSTRAP_ADMIN`：第一个授权管理员的平台主体，只在本组件还没有任何管理持有资格时使用。
- 部署的服务证书（`SERVICE_TLS_*`）。系统面只接受 mTLS，部署里每个组件都可以调用它的两个系统方法。
- 身份：`IAM_ISSUER`、`IAM_JWKS_URL`、`DEPLOYMENT_ID`。
- `AUTHZ_GRPC_URL` 指向本组件自己的系统面（`$endpoint:infra/authz:grpc`）。
- 身份成员的系统面：`IAM_GRPC_URL`（`$endpoint:<身份成员>:grpc`）与 `IAM_COMPONENT`（身份成员的组件 ID，例如 `infra/iam-casdoor`：它出示的证书、账号状态来源的名字）；两者写在装配的共享值里，换身份成员时一起改。身份成员的账号状态流要把 `infra/authz` 列为补取者与读取者（`infra/iam-casdoor` 3.0.17 起）。
- 消息系统：`BUS_URL`（账号状态的事件；事件停了也照样经补取取得，只是慢一些）。

## 依赖说明

- 必需：数据库、消息系统与身份成员（令牌的公钥；账号状态的来源）。
- 可选：`infra/audit`（`AUDIT_GRPC_URL`）；缺时安全变更的审计记录留在本地表，等它上线。

## 配置指南

全部键见 `component.yaml` 的 `configSchema`。

| 键 | 说明 |
| --- | --- |
| `AUTHZ_INSTANCE` | 本成员的实例身份 |
| `AUTHZ_REGISTRY` | 注册表中的属主 |
| `AUTHZ_BOOTSTRAP_ADMIN` | 安装认领 |
| `IAM_GRPC_URL`、`IAM_COMPONENT`（必填） | 身份成员的系统面与组件 ID：账号状态从这里补取与读取 |
| `AUTHZ_SOURCE_HIGH`、`AUTHZ_SOURCE_READ` | `D_src_high`（起始 1 分钟，至多 5 分钟）与 `D_src_read`（起始 10 分钟，至多 1 小时，不短于前者）；调大即放宽撤权的上界，产品说明随之改写（安全 03） |
| `BUS_URL`（必填） | 消息系统 |
| `DEPLOYMENT_ID`、`IAM_ISSUER`、`IAM_JWKS_URL`、`AUTHZ_GRPC_URL`、`SERVICE_TLS_CERT_FILE`、`SERVICE_TLS_KEY_FILE`、`SERVICE_TLS_CA_FILE`（必填） | 受保护的用户面与 mTLS 的系统面要用 |
| `PG_HOST`、`PG_DATABASE`、`PG_USER`、`PG_PASSWORD`、`PG_SCHEMA`（必填） | 自己的数据库，密码是密钥；迁移另用 `PG_OWNER_USER`、`PG_OWNER_PASSWORD` |

## 契约索引

- 系统面：`contract-infra-authz` 的 `be.authz.v3.ViewService/Verify` 与 `be.authz.v3.DefinitionService/Submit`。成员的义务写在那个仓库的 README 里。
- 用户面：

  | 路由 | 操作 | 说明 |
  | --- | --- | --- |
  | `POST /api/authz/changes` | `infra.authz.security_record.change` | 生效点，见下 |
  | `GET /api/authz/changes/{change_key}` | `infra.authz.security_record.change` 或 `.relinquish` | 按变更键查询结果（键在调用者自己的命名空间里；没有绑定的答 `unbound`） |
  | `POST /api/authz/relinquishments` | `infra.authz.security_record.relinquish` | 放弃自己的一整条授予或管理持有资格（D82）：谁也不用授予，本组件给每个持有者一段固定的段 |
  | `GET /api/authz/records?type=` | `infra.authz.security_record.read` | 调用者看得到的有效安全记录：管理者看全部，持有者只看自己的（维度 `holder`） |

`POST /api/authz/changes` 的请求体是安全 09a 的 `be.security.change_request`（`requested_by` 与触发方式由本组件从令牌得出，不在请求里）：

| 方向 | 字段 | 做什么 |
| --- | --- | --- |
| `widen`（新记录） | `candidate`（带 `record_type`：`management_unit`、`management_holding`、`role_revision`、`grant`，可带 `valid` 与 `predecessor`）、`candidate_digest`、可选的 `effective_from` | 建新记录；带 `predecessor` 是续期或扩大（新记录必须包含旧的，生效时旧的以 `superseded` 结束）；`effective_from` 在未来的保存为待生效，到点由本组件进生效点 |
| `tighten` | `target`，可选的 `expected_state_revision`、`expected_revision` | 撤销或放弃整条记录 |
| `tighten` | `target`、`candidate`、`candidate_digest` | 收窄：同一记录的新内容修订，候选必须在原内容之内 |
| `tighten` | `target`、`termination`（`withdraw`、`cancel`）、`expected_state_revision` | 终止尚未生效的记录（收回自己的申请、管理者取消） |
| `neutral` | `target`、`candidate`、`candidate_digest` | 只改管理单元或角色修订的名称 |

`candidate_digest` 是候选在 `be.security.<record_type>` 下的规范形式的摘要（`be-sdk-go` 的 `authz.CandidateDigest`）。同时收紧与放宽的变更拆成两步，先收紧后放宽。

回答是 `be.security.change_result`：`applied`（200）；`processing`、`awaiting_confirmation`、`scheduled`（202）；拒绝是错误，原因见下。生效、终局的拒绝与保存了记录的结果占用变更键：同一个键同样的内容原样返回上次的结果，换了内容答 `CHANGE_KEY_CONFLICT`；处理中与可重试的拒绝不占用，同一个键稍后再交。结果不明时用 `GET /api/authz/changes/{change_key}` 查，没有绑定的答 `unbound`。拒绝的原因：
- `PERMISSION_DENIED`：请求者无权（不管理该单元，或不是记录的持有者）；
- `CONTAINMENT_NOT_PROVEN`：超出管理上限（按单元逐级到根的有效上限），附上是哪个维度；
- `LAST_ADMIN_PROTECTED`：要移除的是最后一个授权管理员；
- `CHANGE_REVISION_STALE`：目标的状态或内容已经变了；
- `REQUEST_INVALID`：请求不成立（例如要求拆成两步）；`DEFINITION_PENDING`：引用的资源定义还在路上，可重试；
- `ADMIN_AVAILABILITY_UNPROVABLE`（处理中）：请求者此刻的资格无法证明（身份来源停住），稍后再交。

## 外壳声明

不是外壳。可以被 Go 的基础外壳（`be/go-infra`）承载。
