# view：组件的视图

`ViewService.Verify`：按已提交的记录重新计算一个组件的分片：授予的有效段（只含注册了、未退役、属主仍定义着的权限键），与暂停范围相交的段整段不给，绑定任职的授予在任职不在职或受授账号不再关联它的员工时整条不给（`employment.Effective`）；主体的账号状态取自身份来源的投影（`JudgeMany`），来源的水位年龄决定完整续发、只为普通读取续发或关闭。每次核验都在主库上重算，不缓存（安全 03）。

## 负责与不负责

- 负责：`Verify`、分片的组装（`place`、`holders`、`definitionsOf`、`Defined.Usable`）、账号状态与续发（`accountsOf`）、已持有摘要的比较。
- 不负责：有效段的求交（`core`）；处置的范围（`effectpoint` 的 `ActiveDispositions`、`Suspended`）。

## 文件

| 文件 | 内容 |
| --- | --- |
| `view.go` | 上面全部 |
| `view_test.go` | 单元测试：分片键、稳定的标识、只有可用的权限键进视图 |
| `helpers_test.go` | 测试用的段与原子 |

## 依赖与被依赖

- 依赖：`core`、`effectpoint`。
- 被依赖：入口（`services.go` 转发）。

## 规则在哪

安全 03（视图与核验、来源的水位）、安全 08（有效段、处置）；“易错点”（仓库根的 `AGENTS.md`）。

## 测试

`view_test.go`；`itest/` 的 `definitionsAndViews`、`identity`、`testEffective`、`dispositions`。
