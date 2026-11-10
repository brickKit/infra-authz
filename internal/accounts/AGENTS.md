# accounts：账号状态变更与账号关联的确认

账号状态变更（安全 08、A134）：身份成员改一个账号的状态之前先问 `AccountService.CheckAccountChange`（要不要确认）；应用账号状态时用掉确认，或标上待补确认（`confirmation_backfill_pending`）；补确认的路由；确认绑定账号、状态与版本。账号与员工的关联（安全 08 第 21 行，C1）：员工成员建立或结束关联之前先问 `CheckLinkChange`；确认绑定员工、账号、动作（`link`、`unlink`）与员工版本；从员工来源应用关联记录时用掉它，不成立的关联照常生效并告警（来源事实）；建立是放宽（有别的可用管理员时所有者不能代替），结束是收紧；`Administrators` 答哪些账号是授权管理员（D62 的提示）。

## 负责与不负责

- 负责：`CheckAccountChange`、`ConfirmAccount`、`AccountChanged`（投影应用账号状态时）、`ReconfirmHTTP`、`AccountPayloadHTTP`；`CheckLinkChange`、`ConfirmLink`、`LinkChanged`（员工来源应用关联时）、`Administrators`、`LinkPayloadHTTP`。
- 不负责：账号状态与员工来源的投影本身（入口建，SDK 的 `projection`）；员工来源的事实（`employment`）；身份侧处置（`effectpoint` 的 `signal.go`）。

## 文件

| 文件 | 内容 |
| --- | --- |
| `accountchange.go` | 账号状态变更 |
| `links.go` | 账号关联的确认、`Administrators` |

## 依赖与被依赖

- 依赖：`core`、`effectpoint`、`employment`。
- 被依赖：`confirmroutes`、入口（系统面、路由、投影的回调）。

## 规则在哪

安全 08 的“管理员账号的状态变更”、A134；安全 08 的“确认与受保护操作”第 3 项与“员工、账号与任职”、D62。

## 测试

`itest/account_integration_test.go`（`TestAccountStatusChanges`）；`itest/links_integration_test.go`（`TestAccountLinks`），改坏检查在装配项目 `dev/rebuild/c1-data/e4c-mutants.txt`。
