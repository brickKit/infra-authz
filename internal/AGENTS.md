# internal/：业务模块

授权成员的业务，每个模块一个包。只给本仓库引用（Go 的 `internal`）：别的组件编译期就引用不了（决定 0101）。先按下表找到模块，再读那个目录的 `AGENTS.md`。

## 模块

| 包 | 一句话 | 依赖（本组件内） |
| --- | --- | --- |
| `effectpoint` | 生效点（安全 08）：每一次变更在全部署的守卫下一个事务里进入：变更键、事实、决策表、按结果写入；变更、收紧、放弃的路由；确认、冷静期、安全处置与解除、身份侧处置、待恢复、影响闭包与到点、预算与再下放 | `core` |
| `view` | `ViewService.Verify`：按已提交的记录重新计算一个组件的视图分片 | `core`、`effectpoint` |
| `definitions` | `DefinitionService.Submit`：组件提交资源与操作定义 | `core` |
| `plans` | 批量计划（A132）：草稿、预览、第二人确认、逐项进生效点、结算、取消与到期 | `core`、`effectpoint` |
| `accounts` | 账号状态变更（A134）：身份成员先问要不要确认、应用时用掉确认或标待补、补确认；账号与员工关联的确认（员工成员先问、应用关联时用掉）、`Administrators` | `core`、`effectpoint`、`employment` |
| `claim` | 安装认领（A130）：没有管理时记下，认领人消耗一次 | `core`、`effectpoint` |
| `restore` | 整套恢复：6.3 按证据重放、6.4–6.5（来源水位、推迟的收紧、不变量检查） | `core`、`effectpoint` |
| `adminrecovery` | 管理员恢复（A129）：部署所有者签名的请求 | `core`、`effectpoint`、`plans` |
| `employment` | 员工来源的事实：关联与任职在本成员里的索引（`authz_employee_fact`） | `core` |
| `confirmroutes` | 确认的两个路由：按对象的种类（记录、处置、计划、账号、关联）分给负责的模块 | `core`、`effectpoint`、`plans`、`accounts` |
| `core`（共用） | 名字与资源定义、记录的字段与包含规则、有效段的求交、决策表、注册表、状态修订、`Base` | — |

分层（每个包只引用比它低的层）：`confirmroutes`、`adminrecovery` → `plans`、`accounts`、`claim`、`restore`、`view` → `effectpoint` → `definitions`、`employment`、`core`。

## 共同的写法

- 每个模块的函数先收 `m *core.Base`，入口包的 `Module` 持有它、登记时适配（`handler`、`job`）。
- **记录的状态只经 `effectpoint.Transition` 写**，它按迁移表（`internal/effectpoint/lifecycle.go`，设计文档里是同一张表）核对，表外的迁移报错；插入记录的地方登记在入口的结构检查里（`authz/structure_test.go`）。
- 一切改变授权状态的写入都经生效点（`effectpoint.Effect`）：先拿 `authz_state` 行的锁（一次一个变更），结果绑定变更键；计划的项、到点的作业、重放、解除都是一次“进入”（`effectpoint.Entry`），不另写记录。
- 生效点改了一条记录的状态，在同一事务里调 `Base.RecordMoved`（入口设成 `plans.FollowRecord`）：计划跟着转，而生效点不依赖计划。
- 每次变更推进状态修订（`core.Advance`）与安全修订；放宽写一般证据，收紧先写意图、生效时写结论（协议 15）。

## 测试

单元：`core`（决策表、包含与求交规则、注册表）、`definitions`（提交的规则）、`effectpoint`（预算、再下放、处置、请求者）、`claim`、`plans`、`view`；流程由 `itest/` 覆盖。
