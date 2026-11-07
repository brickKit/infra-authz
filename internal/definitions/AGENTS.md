# definitions：组件提交定义

`DefinitionService.Submit`：一个组件提交它的资源定义与操作定义（09a 的记录，SDK 封好）。逐份校验（属主与注册表一致 EN21、附件类别落在资源的字段上 EN22、只有副作用仅为 `security_change` 的管理操作可以只收紧 EN24），再交叉检查（视图操作在操作之中），按版本与摘要幂等地保存。

## 负责与不负责

- 负责：`Submit`、逐份的 `check`、`crossCheck`、属主不符的审计。
- 不负责：注册表本身（`core`）；定义怎样进视图（`view`）。

## 文件

| 文件 | 内容 |
| --- | --- |
| `submit.go` | 上面全部 |
| `submit_test.go` | 单元测试：交叉检查、逐份的规则（EN21、EN22、EN24） |

## 依赖与被依赖

- 依赖：`core`。
- 被依赖：入口（`services.go` 转发）。

## 规则在哪

安全 06、09a；`docs/design.md` 的“提交”。

## 测试

`submit_test.go`；`itest/authz_integration_test.go` 的 `definitionsAndViews`。
