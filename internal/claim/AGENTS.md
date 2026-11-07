# claim：安装认领

安装认领（安全 08、A130）：成员第一次启动、还没有任何管理时，记下 `AUTHZ_INSTALL_CLAIM` 指定的认领（一个平台主体，或一次性代码的摘要）；认领人在 `POST /api/authz/claim` 消耗一次，得到根单元与它的管理员持有。

## 负责与不负责

- 负责：`RecordClaim`（入口的 `Start` 调）、`ClaimHTTP`、默认的有效期。
- 不负责：根单元与持有的写入规则（生效点）。

## 文件

| 文件 | 内容 |
| --- | --- |
| `claim.go` | 上面全部 |
| `claim_test.go` | 单元测试：`AUTHZ_INSTALL_CLAIM` 只有两种形式（主体、一次性代码的摘要） |

## 依赖与被依赖

- 依赖：`core`、`effectpoint`。
- 被依赖：入口。

## 规则在哪

安全 08、A130。

## 测试

`claim_test.go`；`itest/` 的测试部署由认领开始（`startE2E`）。
