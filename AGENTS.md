# infra/authz

授权成员的代码。用法与边界在 `BRICKKIT.md`，为什么这样设计（术语、数据、规则、实现状态、未决问题）在 [docs/design.md](docs/design.md)；依据是装配项目 be-assembly-standard 的安全 03（视图与核验）、04（管理上限）、07（包含证明）、08（生效点与记录）、09a（记录与错误），以及 `contract-infra-authz` 的 README（成员的义务）。

## 代码地图

| 文件 | 内容 |
| --- | --- |
| `authz/definition.go` | 组件定义、配置键、本组件自己的资源与操作 |
| `authz/module.go` | 系统面与用户面的注册、启动时的状态行与安装认领 |
| `authz/submit.go` | `DefinitionService.Submit`：注册表、逐份校验、版本与幂等 |
| `authz/view.go` | `ViewService.Verify`：按已提交的记录重新计算一个组件的分片 |
| `authz/effect.go` | 生效点：变更键、管理资格、包含证明、最后管理员、推进修订、审计 |
| `authz/security.go` | 记录的字段、逐维的包含规则 |
| `cmd/seed`（`make seed`） | 种子：给单元管理员授予本组件自己的操作；角色、授予与管理单元由定义那些操作的组件的种子建立 |
| `authz/migrations/` | 表 |
| `docs/design.md` | 设计：术语、数据、规则、命令、实现状态、未决问题 |

## 构建与测试

- `go test ./...`：单元测试，覆盖包含规则的每一行、注册表、提交的交叉检查与合并安全。
- `go test -tags integration ./authz/`：
  - 依赖：本机的 PostgreSQL（环境变量 `AUTHZ_IT_PG_PASSWORD`），以及 be-sdk-go 的 `sectest` 测试部署；
  - 覆盖：提交的规则；视图经 SDK 自己的客户端打开；越权授出被拒；撤权在下一次核验里消失；变更键；最后管理员；审计。
- `brickkit lint`

## 设计取舍

- **视图每次核验都在主库上重新计算，不缓存**（安全 03）。代价随授予数量增长，第 5 步的格里实测。
- **生效点用一把全部署的锁**（`authz_state` 行的 `FOR UPDATE`），变更一个接一个；治理域的细分以后再定。
- **安全修订只有一个域**（`authz.security.deployment`）：任何变更都使所有组件的视图摘要改变，各组件在下一次核验时取新视图。
- **最终的拒绝绑定变更键**：在第二个事务里写入，使同键重试得到同一结果。冲突不绑定。

## 易错点

- 视图里的段要带 `source`（授予的记录）与 `definition`（所依据的资源定义），否则 SDK 的 schema 校验会整份拒绝。
- 包含规则表里没有的原子组合，答“无法证明”，不能为了通过而删掉难比较的条件。

## 改代码前自查

- 改了视图的形状：先用 SDK 的 `GRPCSource` 打开一次（集成测试里有）。
- 改了版本号吗？每次改动都升版本。

<!-- brickkit:managed:begin lang=zh -->
<!-- 由 brickkit 维护（init、add、remove、upgrade、skills update）：这对标记之间的改动会被覆盖 -->

## BrickKit

这是一个 BrickKit 组件：平台只读 `component.yaml`。它依赖的规则：

- `configSchema` 的键就是代码读的环境变量名。不能用保留名：`COMPONENT_ID`、`COMPONENT_VERSION`、`PORT`、`BRICKKIT_SERVED_MEMBERS`、`BRICKKIT_SERVED_MEMBERS_CONFIG`，以及任何 `*_ENDPOINT`。
- 依赖写精确版本。依赖的地址以 `<ID>_ENDPOINT` 注入；缺席的可选依赖根本没有这个变量，读的时候要带兜底。
- `/healthz` 只查本进程，不查依赖。迁移命令用同一个镜像跑，遇到不认识的参数必须直接失败；`local.migrationCommand` 从源码跑同一条迁移，给 `mode: local` 用。
- `BRICKKIT.md` 会随版本进入每个使用它的项目，在那里是脱离仓库单独读的：跟代码一起改，不放相对链接。
- 发版：改 `metadata.version`，提交、推送，`brickkit release`。`brickkit lint` 会检查清单和这些文档——在项目里、在这个目录下跑，只查这个组件（`--all` 查整个项目）。
- 完整规则在 `brickkit-component` 技能里（装了技能的项目或仓库根目录下的 `.claude/skills/brickkit-component/SKILL.md`；`brickkit skills update` 会装上）；参数问 `brickkit <命令> --help`；BrickKit 自己的文档用 `brickkit docs` 看。
<!-- brickkit:managed:end -->
