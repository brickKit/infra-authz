# authz/：入口与组装

组件对外的一个包：`main.go` 与外壳只引用它（`authz.Definition()`、`authz.New`）。这里只**组装**：读配置建 `core.Base`（部署与实例、注册表、来源的界限、单元层数、计划的界限），建账号状态的投影，把 `internal/` 下模块的函数登记成 SDK 要的路由、系统面、作业、订阅、启动钩子、证据的重放与恢复核对；业务一行也不写。

## 负责与不负责

- 负责：组件定义、配置键（`Keys`）、迁移；启动的前提（`DEPLOYMENT_ID`、注册表能解析、来源的界限、`AUTHZ_T_TIGHT`、单元层数、计划的界限、能拨通身份成员）；账号状态变化时依次调的几个模块（`accounts.AccountChanged`、身份侧处置、闭包、最后管理员）；`Base.RecordMoved` 接到 `plans.FollowRecord`；路由、作业、系统面（只许的调用方）；整套恢复的核对（`RecoveryChecks`）。
- 不负责：业务规则（去 [internal/AGENTS.md](../internal/AGENTS.md) 找模块）；名字（`internal/core/names.go`）；集成测试（`itest/`）。

## 文件

| 文件 | 内容 |
| --- | --- |
| `definition.go` | 迁移、`Keys`、`Definition()`（名字与版本在 `core`） |
| `module.go` | `Module` 与 `New`；`Subscriptions`、`Routes`、`Jobs`、`Replays`、`Start`（状态行、实例、没有管理时记下安装认领）；`handler`、`job` 适配 |
| `services.go` | 系统面的登记与转发：`Verify` → `view`、`Submit` → `definitions`、`CheckAccountChange` → `accounts`、`Sources`、`ReplayDeferred`、`Check` → `restore` |
| `checks.go` | 整套恢复的核对（线协议第 14 章，SDK 的 `CheckService`，只许恢复工具调用）：本组件审计过的对象按版本答“还在不在”（`Presence`）；授权状态的不变量另由契约的 `RecoveryService.Check` 做（`restore`） |
| `manifest_test.go` | 单元测试：清单的 `configSchema`；合并安全（入口与 `internal/` 下全部包） |
| `migrations/` | 表 |

## 依赖与被依赖

- 依赖：`internal/` 下全部包。
- 被依赖：`main.go`、外壳 `be/go-infra`、`itest/`。

## 测试

`go test ./authz/`。
