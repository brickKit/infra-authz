# restore：整套恢复

整套恢复中本成员的两步：第 6.3 步按证据重放（`Replay`：证据记下的请求再进生效点，事实里的业务前置条件放过，新建的记录沿用证据的身份）；第 6.4–6.5 步（契约的 `RecoveryService`，只许恢复工具调用）：来源水位是否已越过（`Sources`）、推迟的只有意图的收紧（`ReplayDeferred`：会结束管理员持有资格且之后可证明为零的不执行，持有人以 `recovery_review` 处置关闭）、不变量检查（`Check`：全量记账、关闭复核主体、判最后管理员）。

## 负责与不负责

- 负责：`Replay`、`Sources`、`ReplayDeferred`、`Check`、`RecoveryTool`。
- 不负责：本组件审计过的对象“还在不在”的核对（入口的 `checks.go`）；管理员恢复（`adminrecovery`）。

## 文件

| 文件 | 内容 |
| --- | --- |
| `replay.go` | 6.3 的重放 |
| `recoverystep.go` | 6.4–6.5 |

## 依赖与被依赖

- 依赖：`core`、`effectpoint`。
- 被依赖：入口（证据的重放、系统面）。

## 规则在哪

装配项目的协议 15（整套恢复的第 6 步）、线协议 P12.19–P12.21、A142。

## 测试

`itest/evidence_integration_test.go`（`TestTheReplayAppliesTheEvidenceAgain`）、`itest/recoverystep_integration_test.go`、`itest/signal_integration_test.go` 的 `identitySideRecovery`。
