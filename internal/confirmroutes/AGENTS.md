# confirmroutes：确认的路由

`POST /api/authz/confirmations` 与 `GET /api/authz/confirmations/owner-payload` 两个路由：一个入口确认四种对象，按请求里的字段分给负责的模块：处置的解除（`effectpoint.ConfirmDisposition`）、批量计划（`plans.ConfirmPlan`）、账号的状态变更（`accounts.ConfirmAccount`）、已保存的记录（`effectpoint.Confirm`）；每种对象先按它要的操作检查授权。只做分派，确认的规则在各模块。

## 负责与不负责

- 负责：`ConfirmHTTP`、`OwnerPayloadHTTP`（部署所有者要签的内容）。
- 不负责：确认的规则与记录（`effectpoint` 的 `confirm.go`、`plans`、`accounts`）。

## 文件

| 文件 | 内容 |
| --- | --- |
| `confirmroutes.go` | 上面两个路由 |

## 依赖与被依赖

- 依赖：`core`、`effectpoint`、`plans`、`accounts`。
- 被依赖：入口（路由）。

## 规则在哪

安全 08 的确认记录、09a 的 `be.security.confirmation`、A123、A124。

## 测试

`itest/` 的 `testConfirmations`、`testProtected`、`releases`、`plans`、`TestAccountStatusChanges`。
