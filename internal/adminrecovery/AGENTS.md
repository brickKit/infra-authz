# adminrecovery：管理员恢复

管理员恢复（安全 08、A129）：没有可用的管理员时，部署所有者用离线保存的恢复密钥签名一份请求（`cmd/recover`），`POST /api/authz/recovery` 核对签名（只用一次）后执行：恢复（给一个身份新的管理员持有，留在待恢复里的新一代）、撤换（以所有者的处置暂停被入侵的管理员持有，取消它待生效的变更）、中止。

## 负责与不负责

- 负责：`RecoveryRequest`（`cmd/recover` 用它构造请求）、`RecoveryHTTP`。
- 不负责：待恢复的进入（`effectpoint` 的 `pending.go`）；整套恢复（`restore`）。

## 文件

| 文件 | 内容 |
| --- | --- |
| `recovery.go` | 签名请求的核对、撤换、恢复、中止 |

## 依赖与被依赖

- 依赖：`core`、`effectpoint`、`plans`（撤换时复核被替换的计划项）。
- 被依赖：入口（路由）、`cmd/recover`。

## 规则在哪

安全 08 的管理员恢复、A129。

## 测试

`itest/recovery_integration_test.go`（`recovery`）。
