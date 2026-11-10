# infra/authz

授权成员的代码。用法与边界在 `BRICKKIT.md`，为什么这样设计（术语、数据、规则、实现状态、未决问题）在 [docs/design.md](docs/design.md)；依据是装配项目 be-assembly-standard 的安全 03（视图与核验）、04（管理上限）、07（包含证明）、08（生效点与记录）、09a（记录与错误），以及 `contract-infra-authz` 的 README（成员的义务）。

## 代码地图

代码按业务模块分层。**先读这一节，再进目录**：每个代码目录都有自己的 `AGENTS.md`（同目录的 `CLAUDE.md` 让 Claude Code 读这个目录的文件时自动带上它），写这一层负责什么、不负责什么、每个文件、依赖谁、测在哪。

| 目录 | 是什么 |
| --- | --- |
| `main.go` | 单跑的入口 |
| [`authz/`](authz/AGENTS.md) | 入口：组件定义、配置键与组装（建 `core.Base`、账号状态与员工来源的投影，路由、系统面、作业、订阅、启动、证据的重放与恢复核对都在这里登记，转给业务模块）；不写业务 |
| [`internal/`](internal/AGENTS.md) | 业务：下面的模块各一个包；模块之间的依赖表与分层在它的 `AGENTS.md` |
| [`itest/`](itest/AGENTS.md) | 集成测试，按业务流程分文件；它的 `AGENTS.md` 是测试索引 |
| `authz/migrations/` | 表 |
| `cmd/recover` | 部署所有者在部署机上的恢复命令：签名并提交恢复请求（`internal/adminrecovery` 的 `RecoveryRequest`） |
| `cmd/owner-sign` | 部署所有者的工具：安装时生成密钥对；在离线的机器上对成员给出的待签内容签名 |
| `cmd/seed`（`make seed`） | 种子：给单元管理员授予本组件自己的操作；角色、授予与管理单元由定义那些操作的组件的种子建立 |
| `docs/design.md` | 设计：术语、数据、规则、命令、实现状态、未决问题 |

业务模块（`internal/` 下）：

| 模块 | 负责 |
| --- | --- |
| [`effectpoint`](internal/effectpoint/AGENTS.md) | 生效点（安全 08）：每一次变更在全部署的守卫下一个事务里进入；变更、收紧、放弃的路由；确认、冷静期、安全处置与解除、身份侧处置、待恢复、影响闭包与到点、预算与再下放 |
| [`view`](internal/view/AGENTS.md) | `ViewService.Verify`：按已提交的记录重新计算一个组件的视图分片 |
| [`definitions`](internal/definitions/AGENTS.md) | `DefinitionService.Submit`：组件提交资源与操作定义 |
| [`plans`](internal/plans/AGENTS.md) | 批量计划（A132） |
| [`accounts`](internal/accounts/AGENTS.md) | 账号状态变更的确认（A134） |
| [`claim`](internal/claim/AGENTS.md) | 安装认领（A130） |
| [`restore`](internal/restore/AGENTS.md) | 整套恢复：6.3 的重放、6.4–6.5 |
| [`adminrecovery`](internal/adminrecovery/AGENTS.md) | 管理员恢复（A129） |
| [`employment`](internal/employment/AGENTS.md) | 员工成员的水位流在本成员里的事实（关联与任职）；部署没有员工成员时没有 |
| [`confirmroutes`](internal/confirmroutes/AGENTS.md) | 确认的两个路由：按对象的种类分给负责的模块 |

共用的：[`core`](internal/core/AGENTS.md)（名字与资源定义、记录的字段与包含规则、有效段的求交、决策表、注册表、状态修订、`Base`）。

| 想改 | 从这里开始 | 然后 |
| --- | --- | --- |
| 记录能从哪个状态到哪个状态；加一个状态或结束、暂停原因 | `docs/design.md` 的“记录的状态迁移”（与 `internal/effectpoint/lifecycle.go` 同一张表） | `effectpoint.Transition`；`TestTheDesignDocumentHasTheMoves`；`authz/structure_test.go`；迁移里 `authz_record` 的 CHECK 约束 |
| 生效点的一个结果（决策表的一行） | `internal/core/decide.go` | 读事实的 `internal/effectpoint/facts.go`、写入的 `enact.go`；`TestTheDecisionTable`；`itest/` 的 `effectPoint`、`lifecycle` |
| 一个维度的包含规则、原子的求交 | `internal/core/security.go`、`effective.go` | `TestContainmentRules`、`TestAtomIntersection`；安全 07 |
| 视图的形状 | `internal/view` | 先用 SDK 的 `GRPCSource` 打开一次（`itest/` 的 `definitionsAndViews`） |
| 一种新的确认对象 | `internal/effectpoint/confirm.go` 或负责它的模块 | `internal/confirmroutes` 的分派 |
| 处置与解除 | `internal/effectpoint/disposition.go`、`release.go`、`signal.go` | `itest/` 的 `dispositions`、`releases`、`identitySide` |
| 批量计划 | `internal/plans` | `itest/plans_integration_test.go` |
| 一个配置键 | `authz/definition.go` 的 `Keys`、`authz/module.go` 的 `New` | `component.yaml` 的 `configSchema`、`BRICKKIT.md`；`TestTheManifestDeclaresWhatTheSDKReads` |

## 构建与测试

- `make test`（`go vet ./... && go test ./...`）：单元测试，覆盖决策表、包含规则与求交规则的每一行、上限链、注册表、提交的规则与交叉检查、预算、再下放、清单与合并安全（入口与 `internal/` 下全部包）。
- `make test-integration`（`go test -count=1 -tags integration ./itest/`）：对本机的 PostgreSQL（`AUTHZ_IT_PG_PASSWORD`）与 be-sdk-go 的 `sectest` 测试部署；每个文件测哪条流程、各步的顺序，在 [itest/AGENTS.md](itest/AGENTS.md)。覆盖提交的规则、生效点、视图经 SDK 自己的客户端打开、越权授出被拒、撤权在下一次核验里消失、变更键、最后管理员、审计；身份来源（测试里的替身组件 `test/iam`：只声明账号状态流，SDK 给它挂上补取与读取）：账号的安全状态版本与停用进视图、旧版本的令牌在本组件的用户面答 `TOKEN_STALE`、来源停住时先只为普通读取续发再关闭、恢复后完整续发。消息系统用 `pgqueue://`，放在每次重建的 schema `authz_it_bus`：共用的消息系统上会收到以前几次运行的部署的事件，按 P9.11 会把来源判为 `blocked`。
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
