# effectpoint：生效点

安全 08 的生效点：每一次变更作为一次“进入”（`Entry`），在全部署的守卫（`authz_state` 行的 `FOR UPDATE`）下一个事务里完成：变更键的绑定、读事实、决策表、按结果写入、再绑定。用户的请求、到点的作业、计划的项、整套恢复的重放、处置与解除都从这里进。处置、解除、确认、冷静期与闭包都是同一套记录状态与同一张决策表的一部分，所以在同一个包里（见“文件”的分组）。

## 负责与不负责

- 负责：进入与结果（`Effect`、`Entry`、`Request`、`ChangeResult`、`Denied`）；事实（`facts.go`）；按结果写记录（`enact.go`）与状态迁移（`Transition`）；用户面的变更、收紧、放弃、按键查询与记录列表（`routes.go`）；确认记录（`Confirm`、`ConfirmDisposition`、`UseConfirmations`）；冷静期；安全处置、身份侧处置与解除；待恢复与最后管理员（`JudgeAdmins`）；影响闭包与到期（`Closure`、`Expiry`、`CloseAfter`）；到点的作业（`Due`）；预算与再下放。
- 不负责：决策表本身与包含、求交规则（`core`）；计划的状态（`plans`，经 `Base.RecordMoved` 得知记录迁移）；账号状态变更的确认（`accounts`）；确认路由的分派（`confirmroutes`）。

## 文件

| 文件 | 内容 |
| --- | --- |
| **进入与写入** | |
| `change.go` | 生效点的入口：请求（09a 的 `be.security.change_request`）、结果、`Entry`、`Plan`（每个结果要写什么）；守卫下的一次进入：变更键的绑定、事实、决策表、按结果写入、绑定；证据（收紧之前写意图，生效时写结论或“已取消”，放宽写一般记录，3.0.27）；拒绝的审计 |
| `facts.go` | 读事实：新的放宽（候选）、已有记录的变更（终止、撤销、放弃、收窄）、到点的已保存记录；管理资格（`StandingOf`）与包含证明 |
| `requester.go` | 请求者的资格：管理资格 ∩ 身份来源证明的账号（此刻按 `D_src_high`；不能时按最后已应用的事实，`JudgeApplied`，并判断要不要第二人：超过 `T_tight`、没有水位或来源 `stalled`）；最后管理员 |
| `target.go` | 被变更的记录：加锁读取、所属单元与持有者、收窄与包含旧记录的判断；对象是否影响授权管理员的可用性（`AffectsAdmins`） |
| `enact.go` | 按结果写记录：新建、保存为待确认或待生效（登记到点的工作项）、生效、结束、收窄；状态迁移后调 `RecordMoved` |
| `effect.go` | 生效点的工具：推进安全修订与审计、包含证明、单元与持有资格的读取 |
| `scheduled.go` | 本组件自己的进入：已保存记录的工作项以派生键 `<记录>:<状态修订>:<触发>` 进生效点（`Due`）；触发有待生效到点、确认齐全、算不出的记录恢复 |
| `routes.go` | 用户面：变更、收紧、放弃本人的记录、按键查询、记录列表；`holder` 维度的事实；`Answer` |
| **确认与冷静期** | |
| `confirm.go` | 确认记录（09a 的 `be.security.confirmation`）：确认人针对已保存的放宽或收紧的对象与修订建立确认；两种依据：其他授权管理员（A123）、部署所有者的签名（A124，`AUTHZ_OWNER_KEY`）；生效点核对（未用过、未过期、对象与修订一致、不是申请人或对象本人、确认人此刻合格），已保存的放宽确认齐全后由工作项进生效点，生效时标为已使用 |
| `cooling.go` | 冷静期（A127）：所有者确认的放宽在别的管理员刚变得不可用时转为待生效；“申请人自己弄得不可用的仍算可用”（CP108）；否决 |
| **处置** | |
| `disposition.go` | 安全处置（A128）：发起（处置上限即管理上限、受保护）、范围内记录转暂停、视图里与暂停范围相交的段整段不给（可证明不相交才放过）、列表 |
| `signal.go` | 身份侧处置：应用账号状态时按转变建立或并入；解除要列出移除的证据 |
| `release.go` | 处置的解除：一次求完、`restore_pending`、谁能解除、绑定处置与修订的确认 |
| `pending.go` | 待恢复：可用管理员可证明为零时进入并记下原因；读取接口 |
| **闭包与约束** | |
| `closure.go` | 影响闭包与依赖索引：来源收紧后按索引找出受影响的记录记账：`source_ended`、`source_narrowed`、`held`（`uncomputable`）、部分越界待复核；索引不完整时扫描并把来源域标为待复核；记录的到期 |
| `budget.go` | 安全 07 的预算：一份授予的段数、值与树的项数、一个人在一个操作上的段数；授予、到点、恢复与解除处置时检查 |
| `delegate.go` | 再下放与管理动作（09a 的 `management_actions`、`max_subdelegation_depth`，A131）：有效动作与层数沿父链求交，`managesWith` |
| **单元测试** | |
| `budget_test.go` | 授予与主体的预算 |
| `delegate_test.go` | 有效动作与层数、`managesWith`、再下放、单元的形状 |
| `disposition_test.go` | 暂停范围除非可证明不相交都算相交 |
| `requester_test.go` | 按最后已应用的事实时要不要第二人（`T_tight`） |
| `helpers_test.go` | 测试用的段与原子（与 `core` 的测试各有一份） |

## 依赖与被依赖

- 依赖：`core`。
- 被依赖：`view`、`plans`、`accounts`、`claim`、`restore`、`adminrecovery`、`confirmroutes`、入口。

## 规则在哪

安全 08（生效点、决策表的 30 行、状态迁移、确认、冷静期、处置、待恢复、闭包）、安全 04（管理上限、再下放）、安全 07（预算）、09a（变更请求与结果的编码）；`docs/design.md`。

## 测试

单元测试见上表；流程在 `itest/`：`effectPoint`、`lifecycle`、`testScheduled`、`testNeutral`、`testEffective`、`testSources`、`testUncomputable`、`testRelinquish`、`testConfirmations`、`staleTightening`、`coolingOff`、`dispositions`、`releases`、`bounded`、`delegation`、`handover`、`identitySide`、`lastAdmin`、`pending`（见 [itest/AGENTS.md](../../itest/AGENTS.md)）。

## 已知的结构问题

19 个文件在一个包里：处置与解除是生效点的计划（`Plan` 带着它们），生效点的入口又按请求的种类调它们，互相引用；要再拆得先把它们改成向生效点登记的种类。见装配项目的结构问题登记 SF05。
