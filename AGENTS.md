# infra/authz

授权成员的代码。用法与边界在 `BRICKKIT.md`，为什么这样设计（术语、数据、规则、实现状态、未决问题）在 [docs/design.md](docs/design.md)；依据是装配项目 be-assembly-standard 的安全 03（视图与核验）、04（管理上限）、07（包含证明）、08（生效点与记录）、09a（记录与错误），以及 `contract-infra-authz` 的 README（成员的义务）。

## 代码地图

| 文件 | 内容 |
| --- | --- |
| `authz/definition.go` | 组件定义、配置键、本组件自己的资源与操作 |
| `authz/module.go` | 系统面与用户面的注册（变更、收紧、确认、按键查询、放弃本人的记录、读取）、`holder` 维度的事实、启动时的状态行与安装认领 |
| `authz/submit.go` | `DefinitionService.Submit`：注册表、逐份校验、版本与幂等 |
| `authz/view.go` | `ViewService.Verify`：按已提交的记录重新计算一个组件的分片（授予的有效段，只含注册了、未退役、属主仍定义着的权限键）；主体的账号状态取自身份来源的投影（`JudgeMany`），来源的水位年龄决定完整续发、只为普通读取续发或关闭 |
| `authz/change.go` | 生效点的入口：用户的变更请求（09a 的 `be.security.change_request`）与作业都作为一次进入，在全部署的守卫下一个事务里：变更键的绑定、事实、决策表、按结果写入、绑定 |
| `authz/decide.go` | 决策表（安全 08 的 30 行）：纯函数，按行序第一条命中 |
| `authz/facts.go` | 读事实：新的放宽（候选）、已有记录的变更（终止、撤销、放弃、收窄）、到点的已保存记录；管理资格与包含证明 |
| `authz/requester.go` | 请求者的资格：管理资格 ∩ 身份来源证明的账号（此刻按 `D_src_high`；不能时按最后已应用的事实，`JudgeApplied`，并判断要不要第二人：超过 `T_tight`、没有水位或来源 `stalled`）；最后管理员 |
| `authz/target.go` | 被变更的记录：加锁读取、所属单元与持有者、收窄与包含旧记录的判断；对象是否影响授权管理员的可用性（`affectsAdmins`） |
| `authz/enact.go` | 按结果写记录：新建、保存为待确认或待生效（登记到点的工作项）、生效、结束、收窄 |
| `authz/scheduled.go` | 本组件自己的进入：已保存记录的工作项以派生键 `<记录>:<状态修订>:<触发>` 进生效点；本版有待生效到点 |
| `authz/effective.go` | 有效段（安全 08）：单元的上限沿父单元求交到根，段与段按安全 07 的原子表求交；视图与生效点的包含证明都用它 |
| `authz/confirm.go` | 确认记录（安全 08、09a 的 `be.security.confirmation`）：确认人针对已保存的放宽或收紧的对象与修订建立确认；两种依据：其他授权管理员（A123）、部署所有者的签名（A124，`AUTHZ_OWNER_KEY`）；生效点核对（未用过、未过期、对象与修订一致、不是申请人或对象本人、确认人此刻合格），已保存的放宽确认齐全后由工作项进生效点，生效时标为已使用 |
| `authz/disposition.go` | 安全处置（安全 08、A128）：发起（处置上限即管理上限、受保护）、范围内记录转暂停、视图里与暂停范围相交的段整段不给（可证明不相交才放过）、列表 |
| `authz/signal.go` | 身份侧处置的派生（安全 08）：应用账号状态时按转变建立或并入；解除要列出移除的证据 |
| `authz/release.go` | 处置的解除（安全 08）：一次求完、`restore_pending`、谁能解除、绑定处置与修订的确认 |
| `authz/cooling.go` | 冷静期（安全 08、A127）：所有者确认的放宽在别的管理员刚变得不可用时转为待生效；“申请人自己弄得不可用的仍算可用”（CP108）；否决 |
| `cmd/owner-sign` | 部署所有者的工具：安装时生成密钥对；在离线的机器上对成员给出的待签内容签名 |
| `authz/closure.go` | 闭包作业与依赖索引（安全 08 的影响闭包）：来源收紧后按索引找出受影响的记录记账：`source_ended`、`source_narrowed`、`held`（`uncomputable`）、部分越界待复核；索引不完整时扫描并把来源域标为待复核 |
| `authz/effect.go` | 生效点的工具：推进安全修订与审计、包含证明、单元与持有资格的读取 |
| `authz/security.go` | 记录的字段、逐维的包含规则 |
| `cmd/seed`（`make seed`） | 种子：给单元管理员授予本组件自己的操作；角色、授予与管理单元由定义那些操作的组件的种子建立 |
| `authz/migrations/` | 表 |
| `docs/design.md` | 设计：术语、数据、规则、命令、实现状态、未决问题 |

## 构建与测试

- `go test ./...`：单元测试，覆盖决策表、包含规则与求交规则的每一行、上限链、注册表、提交的交叉检查与合并安全。
- `go test -tags integration ./authz/`：
  - 依赖：本机的 PostgreSQL（环境变量 `AUTHZ_IT_PG_PASSWORD`），以及 be-sdk-go 的 `sectest` 测试部署；
  - 覆盖：提交的规则；生效点（`authz_integration_test.go` 的 T4 段，待生效与到点的工作项在 `scheduled_integration_test.go`）；视图经 SDK 自己的客户端打开；越权授出被拒；撤权在下一次核验里消失；变更键；最后管理员；审计；身份来源（测试里的替身组件 `test/iam`，见 `authz/identity_integration_test.go`：只声明账号状态流，SDK 给它挂上补取与读取）：账号的安全状态版本与停用进视图、旧版本的令牌在本组件的用户面答 `TOKEN_STALE`、来源停住时先只为普通读取续发再关闭、恢复后完整续发。
  - 消息系统用 `pgqueue://`，放在每次重建的 schema `authz_it_bus`：共用的消息系统上会收到以前几次运行的部署的事件，按 P9.11 会把来源判为 `blocked`。
- `brickkit lint`

## 设计取舍

- **视图每次核验都在主库上重新计算，不缓存**（安全 03）。代价随授予数量增长，第 5 步的格里实测。
- **生效点用一把全部署的锁**（`authz_state` 行的 `FOR UPDATE`），变更一个接一个；治理域的细分以后再定。
- **安全修订只有一个域**（`authz.security.deployment`）：任何变更都使所有组件的视图摘要改变，各组件在下一次核验时取新视图。
- **最终的拒绝绑定变更键**：在第二个事务里写入，使同键重试得到同一结果。冲突与定义未到（`DEFINITION_PENDING`：注册表里有属主、定义还没到，D77）不绑定；注册表里没有的资源类型是最终拒绝（`REQUEST_INVALID`），绑定。

## 易错点

- 视图里的段要带 `source`（授予的记录）与 `definition`（所依据的资源定义），否则 SDK 的 schema 校验会整份拒绝。
- 包含规则表里没有的原子组合，答“无法证明”，不能为了通过而删掉难比较的条件。

## 改代码前自查

- 改了视图的形状：先用 SDK 的 `GRPCSource` 打开一次（集成测试里有）。
- 改了版本号吗？每次改动都升版本。

<!-- brickkit:managed:begin lang=zh -->
<!-- 由 brickkit 维护（init、add、remove、upgrade、skills update）：这对标记之间的改动会被覆盖 -->

## BrickKit

这是一个 BrickKit 组件：平台只读 `component.yaml`。它依赖的规则：

- `configSchema` 的键就是代码读的环境变量名。不能用保留名：`COMPONENT_ID`、`COMPONENT_VERSION`、`PORT`、`BRICKKIT_SERVED_MEMBERS`、`BRICKKIT_SERVED_MEMBERS_CONFIG`，以及任何 `*_ENDPOINT`。
- 依赖写精确版本。依赖的地址以 `<ID>_ENDPOINT` 注入；缺席的可选依赖根本没有这个变量，读的时候要带兜底。
- `/healthz` 只查本进程，不查依赖。迁移命令用同一个镜像跑，遇到不认识的参数必须直接失败；`local.migrationCommand` 从源码跑同一条迁移，给 `mode: local` 用。
- `BRICKKIT.md` 会随版本进入每个使用它的项目，在那里是脱离仓库单独读的：跟代码一起改，不放相对链接。
- 发版：改 `metadata.version`，提交、推送，`brickkit release`。`brickkit lint` 会检查清单和这些文档——在项目里、在这个目录下跑，只查这个组件（`--all` 查整个项目）。
- 完整规则在 `brickkit-component` 技能里（装了技能的项目或仓库根目录下的 `.claude/skills/brickkit-component/SKILL.md`；`brickkit skills update` 会装上）；参数问 `brickkit <命令> --help`；BrickKit 自己的文档用 `brickkit docs` 看。
<!-- brickkit:managed:end -->
