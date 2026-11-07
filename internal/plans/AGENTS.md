# plans：批量计划

批量计划（安全 08、A132）：草稿、项的校验、预览（记下目标修订、估算原子比较次数）；超过阈值的计划由第二人确认（绑定计划与摘要）；执行时工作项逐项以 `plan:<计划>:<项>:<尝试>` 进生效点，每项有自己的状态（已应用、已拒绝、待复核），从不给整批一个成功；记录迁移时待复核的项跟着转（`FollowRecord`）；结算、取消与到期。

## 负责与不负责

- 负责：计划与项的表、路由（建立、读取、预览、确认、取消、复核一项）、`ConfirmPlan`、`RunPlan`、`ExpirePlan`、`FollowRecord`、`JobPlan`、`JobPlanExpiry`、默认的期限与阈值。
- 不负责：每一项的判断（生效点）；确认路由的分派（`confirmroutes`）。

## 文件

| 文件 | 内容 |
| --- | --- |
| `plan.go` | 草稿、项的校验、预览、计划与项的状态、到期的登记 |
| `planrun.go` | 执行：工作项逐项进生效点、项的状态表、记录迁移时跟着转、结算、取消与到期 |
| `planhttp.go` | 路由、第二人确认（绑定计划与摘要）、09a 的编码 |
| `plan_test.go` | 单元测试：一次执行的结果到项的状态（安全 08 的项表）、项的键带尝试次数 |

## 依赖与被依赖

- 依赖：`core`、`effectpoint`。
- 被依赖：`adminrecovery`（撤换时复核被替换的项）、`confirmroutes`、入口（路由、作业、`RecordMoved`）。

## 规则在哪

安全 08 的批量计划、A132；`docs/design.md`。

## 测试

`plan_test.go`；`itest/plans_integration_test.go`（`plans`、`planEnds`）。
