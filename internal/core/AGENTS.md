# core：共用的名字、规则与 Base

每个模块都用的部分：组件与资源的名字、记录的字段与逐维的包含规则、有效段的求交、生效点的决策表（纯函数）、注册表、状态修订，以及模块共用的 `Base`。不依赖本组件的任何别的包。

## 负责与不负责

- 负责：`ID`、`Version`、资源与操作的键、`Holder`、`AccountStream`、来源的默认与上限（`DefaultSourceHigh` 等）、`Definitions()`；记录体（`GrantBody`、`HoldingBody`、`UnitBody`、`RoleBody`、`Record`）与包含规则（`Contained`、`Covers`）；有效段（`Limits`、`NewLimits`，单元的上限沿父单元求交到根）；决策表（`Decide`、`Facts`、`Verdict`，安全 08 的 30 行，按行序第一条命中；`ReplayFacts`：重放放过业务前置条件）；注册表（`Registry`、`ParseRegistry`、`RegistryNow`：`AUTHZ_REGISTRY` 变了才重新解析）；状态修订（`State`、`ReadState`、`Advance`）；`UUIDText`；`Base`。
- 不负责：读事实、写记录（`effectpoint`）；视图的组装（`view`）；提交的校验（`definitions`）。

## 文件

| 文件 | 内容 |
| --- | --- |
| `names.go` | 组件与版本、资源与操作的键、维度、账号状态流、来源的默认与上限、`Definitions()` |
| `security.go` | 记录的字段、逐维的包含规则（`self` 两边都按受授人实例化） |
| `effective.go` | 有效段（安全 08）：单元的上限沿父单元求交到根（按受授人，`OfFor`），段与段按安全 07 的原子表求交；视图与生效点的包含证明都用它 |
| `decide.go` | 决策表（安全 08 的 30 行）与它的事实：纯函数，按行序第一条命中；`ReplayFacts` |
| `registry.go` | 注册表：资源类型与权限键的属主、退役日期 |
| `state.go` | 部署的状态行：状态修订的读取与推进；`UUIDText` |
| `base.go` | `Base`：运行时、部署与实例、注册表的缓存、账号状态的投影与来源的界限、单元层数、计划的界限、`RecordMoved` |
| `decide_test.go` | 单元测试：决策表的每一行 |
| `effective_test.go` | 单元测试：原子与段的求交、上限链、退役的权限键 |
| `security_test.go` | 单元测试：包含规则的每一条、注册表 |

## 依赖与被依赖

- 依赖：无（本组件内）。
- 被依赖：全部模块与入口。

## 规则在哪

安全 07（原子与包含）、安全 08（决策表、有效段）、09a（记录的编码）；`docs/design.md`。

## 测试

`go test ./internal/core/`。
