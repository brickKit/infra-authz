# infra/authz

## 组件定位

授权成员，做三件事：
- 接收每个组件启动时提交的定义（资源、维度、字段、操作）；
- 保存安全记录，只在生效点改变它们；记录有管理职责单元与持有、角色修订、授予；
- 每个组件核验视图时，在主库上按已提交的记录重新计算它的视图并回答。

授予不能超出授出者的管理上限：生效点现场做包含证明（安全 07），不复用旧的见证。最后一个授权管理员不能被移除。每个生效的变更都推进安全修订号，并与审计记录同一事务写入。

本组件的用户面也受授权保护，它向自己核验自己的视图，与其他组件一样。

当前版本是代表部署实验第 5 步做到的范围。下面这些没有做，用到时答“能力不支持”（`CAPABILITY_UNSUPPORTED`）：
- 确认与受保护操作；
- 严格路径（A、B 档）；
- 成员切换；
- 共享、委托与扮演；
- 任职关联的授予；
- 包含证明里沿一个维度拆分；
- `relation` 与 `record` 维度。

安装认领做了简化：配置里的主体成为第一个授权管理员。

## 部署前准备

- 数据库：PostgreSQL 16 及以上；schema `infra_authz`，属主角色 `infra_authz_owner`（只供迁移）与运行角色 `infra_authz_rw`，名字来自装配项目的注册表。三者由部署方在第一次启动前建好（be-assembly-standard 的 `make db-init` 按装配进项目的组件配置生成并执行）；表由本组件的迁移建。
- `AUTHZ_INSTANCE`：安装时生成一个 UUID，随部署的运行档案保存，以后不再改变。本组件发现库里记的实例与配置不同时，拒绝启动。
- `AUTHZ_REGISTRY`（通常写成 `file://`，或用 `AUTHZ_REGISTRY_FILE`）：
  - 资源类型与权限键的属主，由装配从注册表生成；
  - 格式是 TSV，三列为 `kind`、`key`、`owner_component`，`kind` 取 `resource_type` 或 `permission`；
  - 本组件自己的键也要在里面。
- `AUTHZ_BOOTSTRAP_ADMIN`：第一个授权管理员的平台主体，只在本组件还没有任何管理持有资格时使用。
- 部署的服务证书（`SERVICE_TLS_*`）。系统面只接受 mTLS，部署里每个组件都可以调用它的两个系统方法。
- 身份：`IAM_ISSUER`、`IAM_JWKS_URL`、`DEPLOYMENT_ID`。
- `AUTHZ_GRPC_URL` 指向本组件自己的系统面（`$endpoint:infra/authz:grpc`）。

## 依赖说明

- 必需：数据库与身份成员（令牌的公钥）。
- 可选：`infra/audit`（`AUDIT_GRPC_URL`）；缺时安全变更的审计记录留在本地表，等它上线。

## 配置指南

全部键见 `component.yaml` 的 `configSchema`。

| 键 | 说明 |
| --- | --- |
| `AUTHZ_INSTANCE` | 本成员的实例身份 |
| `AUTHZ_REGISTRY` | 注册表中的属主 |
| `AUTHZ_BOOTSTRAP_ADMIN` | 安装认领 |
| `DEPLOYMENT_ID`、`IAM_ISSUER`、`IAM_JWKS_URL`、`AUTHZ_GRPC_URL`、`SERVICE_TLS_CERT_FILE`、`SERVICE_TLS_KEY_FILE`、`SERVICE_TLS_CA_FILE`（必填） | 受保护的用户面与 mTLS 的系统面要用 |
| `PG_HOST`、`PG_DATABASE`、`PG_USER`、`PG_PASSWORD`、`PG_SCHEMA`（必填） | 自己的数据库，密码是密钥；迁移另用 `PG_OWNER_USER`、`PG_OWNER_PASSWORD` |

## 契约索引

- 系统面：`contract-infra-authz` 的 `be.authz.v3.ViewService/Verify` 与 `be.authz.v3.DefinitionService/Submit`。成员的义务写在那个仓库的 README 里。
- 用户面：

  | 路由 | 操作 | 说明 |
  | --- | --- | --- |
  | `POST /api/authz/changes` | `infra.authz.security_record.change` | 生效点，见下 |
  | `GET /api/authz/records?type=` | `infra.authz.security_record.read` | 有效的安全记录 |

`POST /api/authz/changes` 的请求体带 `change_key` 与 `action`。`action` 取下面之一：

| `action` | 做什么 |
| --- | --- |
| `unit.create` | 在 `unit` 下建子职责单元，带 `managed_scope` 与 `grantable_operations`，必须被父单元包含 |
| `holding.create` | 让 `holder` 持有 `unit`；`system_role` 可以是 `authorization_admin` |
| `holding.end` | 结束 `target` |
| `role.create` | `name` 与 `segments_template` |
| `grant.create` | 在 `unit` 下授予 `grantee`，带 `segments` 或 `role_revision` |
| `grant.revoke` | 撤销 `target` |

已绑定的变更键原样返回上次的结果，换了内容答 `CHANGE_KEY_CONFLICT`。其他拒绝的原因：
- `PERMISSION_DENIED`：请求者不管理该单元；
- `CONTAINMENT_NOT_PROVEN`：超出上限，附上是哪个维度；
- `LAST_ADMIN_PROTECTED`：要移除的是最后一个授权管理员；
- `CHANGE_REVISION_STALE`：目标已不是有效记录。

## 外壳声明

不是外壳。可以被 Go 的基础外壳（`be/go-infra`）承载。
