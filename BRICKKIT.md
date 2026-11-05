# infra/authz

## 组件定位

授权成员，做三件事：
- 接收每个组件启动时提交的定义（资源、维度、字段、操作）；
- 保存安全记录，只在生效点改变它们；记录有管理职责单元与持有、角色修订、授予；
- 每个组件核验视图时，在主库上按已提交的记录重新计算它的视图并回答。

定义的提交（安全 09a）：只接受提交者自己的定义——`authority`、资源类型与权限键在注册表里的属主都是它，否则拒绝（`DEFINITION_OWNER_MISMATCH`）并在本组件的审计里记一条安全事件；附件类别对应的字段必须是这个资源的字段；`tightening_only` 只给用途为 `manage`、副作用只有 `security_change` 的操作。资源新增了维度之后，以前的授予缺这一维的原子，不进视图（不当作这一维不限），收窄或续期写上这一维后才重新生效（3.0.23 起）；明确为空的集合、组织树与区间也不进视图。

授予不能超出授出者的管理上限：生效点现场做包含证明（安全 07），不复用旧的见证。最后一个授权管理员不能被移除。每个生效的变更都推进安全修订号，并与审计记录同一事务写入。

本组件的用户面也受授权保护，它向自己核验自己的视图，与其他组件一样。

账号状态来自身份成员（安全 03 的内部来源）：本组件以带水位的投影保存它（补取、按 ID 批量读取与快照都是身份成员系统面上的标准方法），视图里每个主体带账号是否停用与安全状态版本（入口组件据此判令牌陈旧）。身份来源的水位超过 `AUTHZ_SOURCE_HIGH`（`D_src_high`，起始 1 分钟）时，视图只为普通读取续发，高风险操作在它的有效期过后关闭；超过 `AUTHZ_SOURCE_READ`（`D_src_read`，起始 10 分钟）、或投影还没对齐时，视图关闭，受保护的请求答可重试的 `AUTHORIZATION_VIEW_EXPIRED`。单个账号的状态无法证明时（它的事件被隔离），这个主体不进视图，其他主体照常。部署第一次启动、投影对齐之前，全部视图关闭。

记录有完整的生命周期（安全 08）：待生效的到点生效，来源收紧后视图立即缩小（授予只在治理单元逐级到根的当前上限之内有效），之后由闭包作业把记录记为结束或暂停；持有者可以放弃自己的授予与管理持有资格（`POST /api/authz/relinquishments`）。

受保护的操作要第二个人确认（安全 08）：新建或扩大管理单元、授出管理持有资格，保存为待确认，另一名授权管理员确认后由本组件生效；撤销或收窄别人的授权管理员持有资格，要先附上确认。只有一名授权管理员时，由部署所有者用离线的私钥签名确认（`AUTHZ_OWNER_KEY`）。所有者确认的放宽，如果另一名授权管理员在 24 小时（冷静期）内变得不可用——持有资格结束或暂停，或账号此刻证明不了有效——就保存为待生效、冷静期满才生效，期间任何可用的授权管理员（申请人除外）可以取消它；申请人自己在冷静期内弄得不可用的管理员仍算可用，这时所有者确认不能代替独立确认人。每次使用所有者确认、每次进入冷静期都写审计并记一条错误级日志（本版没有通知通道）。

身份来源停住时，收紧（撤销、收窄、终止尚未生效的记录）照常可以办理（安全 03 的只减少访问的操作）：请求者的资格按身份来源最后已应用的事实判断，来源水位的年龄在 `AUTHZ_T_TIGHT`（起始 1 小时）内一个人办理，超过后、或来源发现回退时，要另一名授权管理员（资格同样按最后已应用的事实判断）或部署所有者确认；结果带 `basis: last_applied`，审计标明“依据未证明为最新”。对象是授权管理员的持有资格、或这样的持有资格所在的管理单元时，不按旧事实办理：请求者或确认人要此刻可证明，否则答处理中。放宽在来源停住时一律不办理。

安全处置（安全 08，3.0.20 起）：有处置权限的管理者在自己管理的治理单元内，暂停一个人在一组段范围内的访问（`POST /api/authz/dispositions`）：他在这个单元及其下级治理的、与范围相交的授予，以及他在这里的管理持有资格转为暂停；处置生效期间，他的任何段（新授予、续期、为他新建的记录都一样）只要与暂停的范围相交，整段不进视图。范围要在单元的管理上限之内；暂停一个人的全部段只能在根单元做。处置其他授权管理员是受保护的收紧。解除（`POST /api/authz/dispositions/{id}/release`）是一次变更：处置仍暂停的记录一起恢复，没剩下有效段的转为待恢复、由本组件之后重试，处置转为已解除；能处置这个治理域的人才能解除（被处置的人自己不行，下级单元的管理者不行）；解除授权管理员的处置是受保护的放宽，确认绑定处置与它的修订。

身份成员冻结一个账号，或把它标为被盗、可疑并停用时，本组件应用这个状态的同时建立一条全局的处置（暂停这个人的全部段，他的生效记录转为暂停）；同一账号再有冻结或标记并入这条处置。身份侧解冻不解除它；解除要由根单元的管理者列出要移除的证据（`signal_refs`，形如 `<账号>@<状态修订>`），全部移除才真正解除。第一次见到就已冻结的账号不算转变。

可证明没有可用的授权管理员时（最后一名被处置、账号被停用等），部署进入待恢复（`GET /api/authz/admin-state`）：新建或扩大管理单元、授出管理持有资格一律答 `RECOVERY_IN_PROGRESS`，普通授予与收紧照常；只能由部署所有者做管理员恢复退出：在部署机上用离线的恢复私钥运行 `recover`（`-action replace -holding <持有资格>` 暂停被盗的管理员，`-action restore -identity <主体>` 恢复一名管理员，`-action abort` 中止），请求发到 `POST /api/authz/recovery`，每个请求只能用一次。恢复会推进授权恢复代次，各组件丢弃旧视图。

包含证明（安全 07，3.0.21 起）：授予里的 `self` 按受授人判断，同一个 `self` 对不同的受授人结果不同；新建管理单元时还没有受授人，单元范围里的 `self` 只包含于父单元的 `self`。授予超出预算时驳回（`CONTAINMENT_NOT_PROVEN`，`detail` 写明哪项）：一份授予在一个资源类型与操作上最多 8 段（3.0.22 起；3.0.21 误按整份授予计，多操作的角色会被驳回），一个值集合最多 1,000 个值，一个组织树原子最多 64 项，一个人在一个资源类型与操作上最多 64 段（生效与待生效的合计）。

批量计划（安全 08，3.0.21 起）：一次改很多条时用。确认后本组件逐项经生效点执行（请求者是发起人，一切照常重查），每一项有自己的结果：已生效、已驳回、待复核（预览后目标变了，或项保存了待确认的记录——那条记录生效或结束时项跟着转）；全部有结果时计划为已完成或部分完成。取消或到期（预览起 `AUTHZ_PLAN_MAX_AGE`，起始 7 天）时没执行的项驳回，项保存的、尚未生效的记录一起取消，已生效的不动。

管理单元（3.0.21 起）必须写明 `management_actions`（`grant`、`revoke`、`edit_role`、`bind_role`、`delegate_management`、`share_governance` 中的几项）与 `max_subdelegation_depth`（下面还能再分几层）：持有单元的人在它及以下只能做它与它以上每个单元都列出的动作；子单元的动作不多于父单元、层数小于父单元；根单元的层数是 `AUTHZ_MAX_UNIT_DEPTH`（起始 6）。

3.0.23 还没有做的，用到时答“能力不支持”（`CAPABILITY_UNSUPPORTED`）：
- 严格路径（A、B 档）；
- 成员切换；
- 共享、委托与扮演；
- 任职关联的授予；
- 包含证明里沿一个维度拆分；
- `relation` 与 `record` 维度。

安装认领：安装时记下的认领由认领人自己消耗一次（`POST /api/authz/claim`），绑定库的部署恢复代次，用旧备份恢复不会重新打开。

## 部署前准备

- 数据库：PostgreSQL 16 及以上；schema `infra_authz`，属主角色 `infra_authz_owner`（只供迁移）与运行角色 `infra_authz_rw`，名字来自装配项目的注册表。三者由部署方在第一次启动前建好（be-assembly-standard 的 `make db-init` 按装配进项目的组件配置生成并执行）；表由本组件的迁移建。
- `AUTHZ_INSTANCE`：安装时生成一个 UUID，随部署的运行档案保存，以后不再改变。本组件发现库里记的实例与配置不同时，拒绝启动。
- `AUTHZ_REGISTRY`（通常写成 `file://`，或用 `AUTHZ_REGISTRY_FILE`）：
  - 资源类型与权限键的属主，由装配从注册表生成；
  - 格式是 TSV，三列为 `kind`、`key`、`owner_component`，`kind` 取 `resource_type` 或 `permission`；已退役的权限键多第四列，写退役日期：退役的键不再给任何访问（授予照旧，视图里它的段为空）；
  - 本组件约 30 秒重读一次这个文件，退役在那之后的下一次核验生效；
  - 本组件自己的键也要在里面。
- `AUTHZ_OWNER_KEY`（通常 `file://`）：部署所有者确认的公钥（Ed25519，PEM）。安装时用 `owner-sign -keygen` 生成密钥对，私钥交部署所有者离线保管。只有一名授权管理员时，新建管理单元与授出管理持有资格都要用它确认；没有配置时这类变更只能由另一名授权管理员确认。
- `AUTHZ_INSTALL_CLAIM`（通常 `file://`）：安装认领，`principal:<平台主体>` 或 `code:sha256:<一次性确认码的摘要>`；第一次启动、还没有任何管理时记下，认领人登录后调 `POST /api/authz/claim`（确认码放在请求体的 `code`）成为第一个授权管理员，只能用一次；`AUTHZ_INSTALL_CLAIM_VALIDITY` 是有效期（起始 7 天）。
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
| `AUTHZ_INSTALL_CLAIM`、`AUTHZ_INSTALL_CLAIM_VALIDITY` | 安装认领与它的有效期 |
| `IAM_GRPC_URL`、`IAM_COMPONENT`（必填） | 身份成员的系统面与组件 ID：账号状态从这里补取与读取 |
| `AUTHZ_SOURCE_HIGH`、`AUTHZ_SOURCE_READ` | `D_src_high`（起始 1 分钟，至多 5 分钟）与 `D_src_read`（起始 10 分钟，至多 1 小时，不短于前者）；调大即放宽撤权的上界，产品说明随之改写（安全 03） |
| `AUTHZ_T_TIGHT` | `T_tight`（起始 1 小时）：身份来源停住时，一个人按最后已应用的事实办理收紧的水位年龄上限；超过后要第二人确认（安全 03） |
| `AUTHZ_OWNER_KEY` | 部署所有者确认的公钥 |
| `AUTHZ_RECOVERY_KEY` | 管理员恢复的公钥（与上一项不是同一对；没有时不受理恢复） |
| `BUS_URL`（必填） | 消息系统 |
| `DEPLOYMENT_ID`、`IAM_ISSUER`、`IAM_JWKS_URL`、`AUTHZ_GRPC_URL`、`SERVICE_TLS_CERT_FILE`、`SERVICE_TLS_KEY_FILE`、`SERVICE_TLS_CA_FILE`（必填） | 受保护的用户面与 mTLS 的系统面要用 |
| `PG_HOST`、`PG_DATABASE`、`PG_USER`、`PG_PASSWORD`、`PG_SCHEMA`（必填） | 自己的数据库，密码是密钥；迁移另用 `PG_OWNER_USER`、`PG_OWNER_PASSWORD` |

## 契约索引

- 系统面：`contract-infra-authz` 的 `be.authz.v3.ViewService/Verify` 与 `be.authz.v3.DefinitionService/Submit`。成员的义务写在那个仓库的 README 里。
- 用户面：

  | 路由 | 操作 | 说明 |
  | --- | --- | --- |
  | `POST /api/authz/changes` | `infra.authz.security_record.change` | 生效点：放宽与中性变更，见下 |
  | `POST /api/authz/tightenings` | `infra.authz.security_record.tighten`（只减少访问） | 生效点：收紧，见下；身份来源停住时照常可用 |
  | `POST /api/authz/confirmations` | 已保存的放宽：`.change`；收紧：`.tighten` | 确认一项受保护的变更或两人规则下的收紧：`target`；收紧另带 `expected_revision`；部署所有者确认另带 `basis: deployment_owner`、`expires_at` 与 `signature`。回答确认的 `id` 与 `expires_at`（201） |
  | `GET /api/authz/confirmations/owner-payload?target=&expected_revision=` | 同上 | 部署所有者要签的内容（`owner-sign` 与种子用） |
  | `GET /api/authz/changes/{change_key}` | `.change`、`.tighten` 或 `.relinquish` | 按变更键查询结果（键在调用者自己的命名空间里；没有绑定的答 `unbound`） |
  | `POST /api/authz/relinquishments` | `infra.authz.security_record.relinquish` | 放弃自己的一整条授予或管理持有资格（D82）：谁也不用授予，本组件给每个持有者一段固定的段 |
  | `POST /api/authz/dispositions` | `infra.authz.security_disposition.dispose`（只减少访问） | 安全处置：`change_key`、`subject`、`domain`（管理单元，缺省为根）、`suspended_segments` 或 `all_scope: true`（只在根）、受保护时的 `confirmation_ids`；回答同变更结果，`record` 是处置的身份 |
  | `GET /api/authz/dispositions` | `infra.authz.security_disposition.read` | 处置的列表 |
  | `POST /api/authz/dispositions/{id}/release` | `infra.authz.security_disposition.release` | 解除：`change_key`、`disposition_revision`、受保护时的 `confirmation_ids`（确认用 `POST /api/authz/confirmations` 的 `disposition` 与 `expected_revision`，所有者待签内容用 `?disposition=`） |
  | `POST /api/authz/plans` | `.change` | 批量计划的草稿（3.0.21 起）：`plan_key` 与 `items`（每项 `item_key` 与不带 `change_key` 的变更请求）；同一个键再交同样的内容回答同一个计划，内容不同答 `CHANGE_KEY_CONFLICT` |
  | `POST /api/authz/plans/{id}/preview`、`/confirm`、`/cancel` | `.change` | 发起人预览（记下各项目标的修订，原子比较次数超过 100,000 驳回）、按 `preview_digest` 确认（项数超过 `AUTHZ_PLAN_CONFIRM_ABOVE` 时另带 `confirmation_ids`：别的授权管理员用 `POST /api/authz/confirmations` 的 `plan` 与 `plan_digest` 确认，缺时答 202 `CONFIRMATION_REQUIRED`）、取消 |
  | `POST /api/authz/plans/{id}/items/{item}/review` | `.change` | 待复核（没有保存记录）的项重新预览后再执行，可带新的 `request`；超过阈值的计划另要绑定 `<项>#<第几次>` 的确认 |
  | `GET /api/authz/plans/{id}` | `.read` | 计划与每一项的状态、结果（发起人或授权管理员） |
  | `GET /api/authz/records?type=` | `infra.authz.security_record.read` | 调用者看得到的有效安全记录：管理者看全部，持有者只看自己的（维度 `holder`） |

两个生效点路由的请求体都是安全 09a 的 `be.security.change_request`（`requested_by` 与触发方式由本组件从令牌得出，不在请求里）；`tighten` 只发往 `/api/authz/tightenings`，发往 `/api/authz/changes` 的答 `REQUEST_INVALID`。收紧可带 `confirmation_ids`（受保护的收紧与两人规则要先确认）。管理者的授予要同时有 `.change` 与 `.tighten`：

| 方向 | 字段 | 做什么 |
| --- | --- | --- |
| `widen`（新记录） | `candidate`（带 `record_type`：`management_unit`、`management_holding`、`role_revision`、`grant`，可带 `valid` 与 `predecessor`）、`candidate_digest`、可选的 `effective_from` | 建新记录；带 `predecessor` 是续期或扩大（新记录必须包含旧的，生效时旧的以 `superseded` 结束）；`effective_from` 在未来的保存为待生效，到点由本组件进生效点 |
| `tighten` | `target`，可选的 `expected_state_revision`、`expected_revision` | 撤销或放弃整条记录 |
| `tighten` | `target`、`candidate`、`candidate_digest` | 收窄：同一记录的新内容修订，候选必须在原内容之内 |
| `tighten` | `target`、`termination`（`withdraw`、`cancel`、`reject`）、`expected_state_revision` | 终止尚未生效的记录（收回自己的申请、管理者取消、确认人拒绝） |
| `neutral` | `target`、`candidate`、`candidate_digest` | 只改管理单元或角色修订的名称 |

`candidate_digest` 是候选在 `be.security.<record_type>` 下的规范形式的摘要（`be-sdk-go` 的 `authz.CandidateDigest`）。同时收紧与放宽的变更拆成两步，先收紧后放宽。

回答是 `be.security.change_result`（请求者按最后已应用的事实判断时带 `basis: last_applied`）：`applied`（200）；`processing`、`awaiting_confirmation`、`scheduled`（202）；拒绝是错误，原因见下。生效、终局的拒绝与保存了记录的结果占用变更键：同一个键同样的内容返回上次的结果，保存了记录的返回它当前的状态（之后生效了答 `applied`，生效前被终止的答 `CHANGE_REVISION_STALE`），换了内容答 `CHANGE_KEY_CONFLICT`；处理中与可重试的拒绝不占用，同一个键稍后再交。结果不明时用 `GET /api/authz/changes/{change_key}` 查，没有绑定的答 `unbound`。拒绝的原因：
- `PERMISSION_DENIED`：请求者无权（不管理该单元，或不是记录的持有者）；
- `CONTAINMENT_NOT_PROVEN`：超出管理上限（按单元逐级到根的有效上限），附上是哪个维度；
- `LAST_ADMIN_PROTECTED`：要移除的是最后一个授权管理员；
- `CHANGE_REVISION_STALE`：目标的状态或内容已经变了；
- `REQUEST_INVALID`：请求不成立（例如要求拆成两步）；`DEFINITION_PENDING`：引用的资源定义还在路上，可重试；
- `ADMIN_AVAILABILITY_UNPROVABLE`（处理中）：请求者或确认人此刻的资格无法证明（身份来源停住），稍后再交；
- `CONFIRMATION_REQUIRED`（`awaiting_confirmation`）：要先确认（受保护的变更、超过 `T_tight` 的收紧）；
- `AUTHORIZATION_UNPROVABLE`（可重试）：身份来源停住时，请求者按最后已应用的事实也不合格，或他的账号被隔离。

## 外壳声明

不是外壳。可以被 Go 的基础外壳（`be/go-infra`）承载。
