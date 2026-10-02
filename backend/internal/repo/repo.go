// Package repo 是 infra-authz 的数据访问层：权限键册镜像、角色模型
// （roles/role_permissions/user_roles，纯并集无 Deny）、stale_since 的
// 来源 role_changes、以及极简部门表。
//
// ⚠️ 这是权限体系里唯一需要自己持久化状态的组件：判定在各组件进程内的
// bundle 里做，状态（谁有什么角色、角色有什么权限）只存在这里。
package repo

import (
	"database/sql"
	"errors"
	"fmt"
)

// ── 哨兵错误。grpc/http 两层通过 service.ToStatus 统一映射 ──

var ErrInvalidArgument = errors.New("参数不合法")
var ErrNotFound = errors.New("not found")

// ErrRoleCodeReserved：用户不许自己建 u: 前缀的角色——那是专属角色的保留
// 前缀，撞了会和"给人单独加权限"这条路径的内部实现冲突。
var ErrRoleCodeReserved = errors.New("角色代码 u: 前缀保留给专属角色，不能手工创建")

type Repo struct {
	db     *sql.DB
	role   string
	schema string
}

func New(db *sql.DB, role, schema string) *Repo {
	return &Repo{db: db, role: role, schema: schema}
}

func personalRoleCode(sub string) string { return "u:" + sub }

func wrap(action string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", action, err)
}

func mapConstraintErr(err error, notFoundMsg string) error {
	switch {
	case isForeignKeyViolation(err):
		return fmt.Errorf("%w: %s", ErrNotFound, notFoundMsg)
	case isUniqueViolation(err):
		return fmt.Errorf("%w: 已存在", ErrInvalidArgument)
	default:
		return err
	}
}
