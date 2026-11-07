# accounts：账号状态变更的确认

账号状态变更（安全 08、A134）：身份成员改一个账号的状态之前先问 `AccountService.CheckAccountChange`（要不要确认）；应用账号状态时用掉确认，或标上待补确认（`confirmation_backfill_pending`）；补确认的路由；确认绑定账号、状态与版本。

## 负责与不负责

- 负责：`CheckAccountChange`、`ConfirmAccount`、`AccountChanged`（投影应用账号状态时）、`ReconfirmHTTP`、`AccountPayloadHTTP`。
- 不负责：账号状态的投影本身（入口建，SDK 的 `projection`）；身份侧处置（`effectpoint` 的 `signal.go`）。

## 文件

| 文件 | 内容 |
| --- | --- |
| `accountchange.go` | 上面全部 |

## 依赖与被依赖

- 依赖：`core`、`effectpoint`。
- 被依赖：`confirmroutes`、入口（系统面、路由、投影的回调）。

## 规则在哪

安全 08 的“管理员账号的状态变更”、A134。

## 测试

`itest/account_integration_test.go`（`TestAccountStatusChanges`）。
