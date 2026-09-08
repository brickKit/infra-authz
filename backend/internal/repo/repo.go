// Package repo 是 infra-authz 的数据访问层：权限键册镜像、角色模型
// （roles/role_permissions/user_roles，纯并集无 Deny）、stale_since 的
// 来源 role_changes、以及阶段三极简部门表。
//
// ⚠️ 这是权限体系里唯一需要自己持久化状态的组件（设计计划身份证 + 阶段三
// 计划 Task 4）——阶段二三个枢纽"零表零迁移"的既有印象在这里不成立。
package repo

import (
	"database/sql"
	"errors"
	"fmt"
)

// ── 哨兵错误。grpc/http 两层通过 service.ToStatus 统一映射（同 erp-finance）──

var ErrInvalidArgument = errors.New("参数不合法")
var ErrNotFound = errors.New("not found")

// ErrRoleCodeReserved：用户不许自己建 u: 前缀的角色——那是专属角色的保留
// 前缀（设计书 §14.1.3），撞了会和"给人单独加权限"这条路径的内部实现冲突。
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
