# itest/：集成测试与测试索引

授权成员对着真实的 PostgreSQL、经它真实的接口的测试（L2）：组件的定义经 mTLS 提交，视图用 SDK 自己的客户端打开，变更由带着测试部署（be-sdk-go 的 `sectest`）令牌的用户在生效点提交，成员用自己的视图守着自己的用户面。身份成员是测试里的替身（`identity_integration_test.go` 的 `iamModule`：只声明账号状态流，SDK 给它挂上补取与读取）。构建标签 `integration`；一条业务流程一个文件。

## 怎样跑

- `make test-integration`（`go test -count=1 -tags integration ./itest/`），约 2 分半。
- 环境变量：`AUTHZ_IT_PG_PASSWORD`（装配项目 `.env` 的 `POSTGRES_PASSWORD`，`be-postgres` 的超级用户）；缺了就失败，不会跳过。
- 前提：装配项目里 `make up` 起了 `be-postgres`；库 `brickkit_test_db`；schema `authz_it` 与消息系统的 schema `authz_it_bus`（`pgqueue://`）每次重建：共用的消息系统上会收到以前几次运行的部署的事件，按 P9.11 会把来源判为 `blocked`；端口 28223（用户面）与 9223（系统面）要空着。
- 每个测试都用 `startE2E` 起一套新的部署：迁移、启动替身身份成员与本成员，Alice 认领安装（`AUTHZ_INSTALL_CLAIM`），等到本成员能核验自己的视图。

## 文件

`TestMemberEndToEnd` 按下表的顺序跑各步（普通的方法调用），后面的步用前面建的单元、持有与授予，所以一步不能单独跑：

| 文件 | 步 | 测的流程 | 被测的模块 |
| --- | --- | --- | --- |
| `authz_integration_test.go` | `definitionsAndViews` | 组件经 mTLS 提交定义，再用 SDK 的客户端打开它的视图 | `definitions`、`view` |
| `authz_integration_test.go` | `effectPoint` | 生效点的第一段：单元、持有、上限之内与之外的授予、变更键、撤销、最后管理员 | `effectpoint` |
| `authz_integration_test.go` | `lifecycle` | T4 的第一部分：收窄、过时的修订、拆分、续期、终止、有效期 | `effectpoint` |
| `scheduled_integration_test.go` | `testScheduled` | T4d：将来生效的放宽保存为待生效、登记到点的工作项；到点以派生键进生效点，全部检查重做 | `effectpoint`（`scheduled.go`） |
| `neutral_integration_test.go` | `testNeutral` | 中性变更：改显示名是新的内容修订，状态修订与安全修订不动；候选里别的改动算改权限，被拒 | `effectpoint` |
| `effective_integration_test.go` | `testEffective`、`testSources` | T4f、T4g：视图给授予的段 ∩ 单元的上限（沿父链到根）；闭包作业对来源收紧的记账；角色修订结束、单元续期、记录自身的有效期、索引说不清的情况 | `core`（`effective.go`）、`effectpoint`（`closure.go`）、`view` |
| `uncomputable_integration_test.go` | `testUncomputable` | 交集算不出的记录暂停（`uncomputable`），算得出时以派生键恢复 | `effectpoint` |
| `relinquish_integration_test.go` | `testRelinquish` | D82：放弃本人的授予或持有，只能是自己的，经生效点 | `effectpoint`（`routes.go`） |
| `confirm_integration_test.go` | `testConfirmations`（含 `testProtected`） | T5a：另一位授权管理员按修订确认收紧，只用一次，不成立的确认被拒；T5b–T5d：受保护的放宽等确认，确认后由作业生效或待生效 | `effectpoint`（`confirm.go`）、`confirmroutes` |
| `identity_integration_test.go` | `identity` | T3：身份成员的账号状态进视图、过时的令牌、来源停住 | `view`、入口的投影 |
| `tighten_integration_test.go` | `staleTightening`（含 `staleCleanup`） | T5e：来源停住时按最后已应用的事实收紧：`T_tight` 之内一人、之外第二人 | `effectpoint`（`requester.go`） |
| `cooling_integration_test.go` | `coolingOff` | A127：所有者确认的放宽在别的管理员刚变得不可用时转为待生效，期间可以否决 | `effectpoint`（`cooling.go`） |
| `disposition_integration_test.go` | `dispositions` | T6a：安全处置暂停范围内的记录，视图里与暂停范围相交的段整段不给 | `effectpoint`（`disposition.go`）、`view` |
| `release_integration_test.go` | `releases` | T6b：一次解除恢复处置还暂停着的全部记录；谁能解除；绑定处置与修订的确认 | `effectpoint`（`release.go`）、`confirmroutes` |
| `bounded_integration_test.go` | `bounded`（含 `budgets`） | T7a：管理两个单元的人只能在各自之内授予；比较不了的条件被拒，不靠删掉通过；安全 07 的预算 | `effectpoint`（`facts.go`、`budget.go`）、`core` |
| `delegation_integration_test.go` | `delegation` | T7b：子单元的动作在父单元之内、层数更低；每种管理动作是自己的权限 | `effectpoint`（`delegate.go`） |
| `handover_integration_test.go` | `handover` | T7c：使用不是管理；角色的新修订不改绑定；管理员卸任 | `effectpoint` |
| `plans_integration_test.go` | `plans`（含 `planEnds`） | T7d：计划的每一项有自己的状态；超过阈值的第二人确认；取消与到期 | `plans`、`confirmroutes` |
| `signal_integration_test.go` | `identitySide`、`identitySideRecovery` | T6c：身份成员冻结一个人，建立全部署的处置；T13b：整套恢复中身份侧处置的信号 | `effectpoint`（`signal.go`）、`restore` |
| `lastadmin_integration_test.go` | `lastAdmin` | T6d：最后管理员不变量（决策表 27–28 行） | `effectpoint`（`requester.go`、`pending.go`） |
| `pending_integration_test.go` | `pending` | T6e：最后一位授权管理员处置自己，部署进入待恢复；期间管理结构的放宽被拒 | `effectpoint`（`pending.go`） |
| `recovery_integration_test.go` | `recovery` | T6f：部署所有者签名的请求只用一次：恢复、撤换、中止 | `adminrecovery` |
| `authz_integration_test.go` | `audited` | 每个生效的变更都在它的事务里审计了 | `effectpoint` |

各自起一套部署、可以单独跑（`-run`）的测试：

| 文件 | 测试 | 测的流程 | 被测的模块 |
| --- | --- | --- | --- |
| `account_integration_test.go` | `TestAccountStatusChanges` | T9d、A134：身份成员改账号状态之前先问；确认绑定账号、状态与版本；待补确认与补确认 | `accounts`、`confirmroutes` |
| `evidence_integration_test.go` | `TestChangesLeaveEvidence` | 放宽生效时写一般证据；收紧先写意图、生效时写结论 | `effectpoint`（`change.go`） |
| `evidence_integration_test.go` | `TestTheReplayAppliesTheEvidenceAgain` | 整套恢复 6.3：数据库回到之前，按提交顺序重放授予与撤销 | `restore`（`replay.go`） |
| `recoverystep_integration_test.go` | `TestTheRecoveryStepAfterTheReplay` | 整套恢复 6.4–6.5：来源水位、不变量检查、推迟的收紧 | `restore`（`recoverystep.go`） |
| `employment_integration_test.go` | `TestTheEmployeeSource` | C1 E4b：员工成员的水位流是第二个内部来源：记录到达事实、变化替换事实、整套恢复 6.4 一起等它 | `employment`、入口、`restore` |
| `links_integration_test.go` | `TestAccountLinks` | C1 E4c：关联的确认绑定员工、账号、动作与员工版本；员工成员先问、什么也不用掉；应用关联时用掉、只用一次；建立时所有者不能代替可用的管理员，结束时可以；`Administrators`；两个方法只答员工成员 | `accounts`、`confirmroutes` |
| `person_integration_test.go` | `TestOnePerson` | C1 E4d：关联到同一员工的两个账号是一个人：互相确认不算（账号状态、记录的放宽）、不能确认本人员工的关联；一条关联结束后又是两个人；处置覆盖这个人的账号，之后关联进来的也逃不掉 | `employment`、`effectpoint`、`accounts`、`view` |
| `appointments_integration_test.go` | `TestAppointmentBindings` | C1 E4e：授予与管理持有绑定任职：授出时账号要关联到任职的员工、任职计划中或在职，还没应用的任职答可重试、到了之后同一个键生效；在职才给；调岗（旧任职结束、新的开始）后旧的立即不给、闭包记为 `source_ended`；关联结束时通过任职的全部结束；不绑定任职的授予不受影响 | `employment`、`effectpoint`、`view` |
| `catalog_integration_test.go` | `TestTheAttachmentCategoryCatalog` | C9：附件成员读得到带类别的定义（属主、类别）、同一修订答“未变”、新版本改变修订、别的组件被拒 | `definitions`（`catalog.go`） |
| `grpcerrors_integration_test.go` | `TestSystemMethodsAnswerTheirReason` | 系统面的拒绝以它自己的原因到达调用方，不是 `INTERNAL` | 入口、`definitions` |

共用的：

| 文件 | 内容 |
| --- | --- |
| `authz_integration_test.go` | `TestMemberEndToEnd`（各步的顺序）；`e2e`（运行中的部署、数据库、替身身份成员、`demo/orders` 的视图）；`startE2E`；`verify`、`segmentsOf`、`inView` |
| `helpers_integration_test.go` | `dial`、`call`、`callAs`、`submitChange`、`listRecords`、`waitForView`、`portFree`；变更请求的构造（`widenReq`、`grantReq`、`unitReq`、`subUnitReq`） |
| `identity_integration_test.go` | 替身身份成员（`iamModule`、`startIAM`）与账号状态的写入 |
| `employment_integration_test.go` | 替身员工成员（`employeeModule`、`startEmployee`：员工、任职、关联的写入）；`startE2E(t, withEmployee)` 连它一起起 |
| `owner_integration_test.go` | 部署所有者的密钥、确认与恢复的签名（`ownerConfirm`、`protect`、`ownerConfirmRelease`） |

## 加测试

新流程加一个文件与一步，在 `TestMemberEndToEnd` 里按依赖排进顺序（或写成自己起部署的测试），在上表加一行；测试不为了通过而改。
