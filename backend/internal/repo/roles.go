package repo

import (
	"context"
	"database/sql"
	"strings"

	besdk "github.com/brickKit/be-sdk-go"
)

// Role 是一条角色定义，PermissionKeys 是它当前挂着的权限键（排过序，
// 方便测试断言与展示都稳定）。
type Role struct {
	Code           string
	Name           string
	IsSystem       bool
	PermissionKeys []string
}

// CreateRole 建一个由管理员命名的角色。u: 前缀保留给专属角色（§14.1.3），
// 手工创建会被拒绝——那条路径只走 EnsureRole。
func (r *Repo) CreateRole(ctx context.Context, code, name string) (*Role, error) {
	if strings.HasPrefix(code, "u:") {
		return nil, ErrRoleCodeReserved
	}
	if code == "" || name == "" {
		return nil, ErrInvalidArgument
	}
	err := besdk.WithTx(ctx, r.db, r.role, r.schema, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx,
			`INSERT INTO roles (code, name, is_system) VALUES ($1, $2, false)`, code, name)
		return err
	})
	if err != nil {
		return nil, mapConstraintErr(err, "")
	}
	return &Role{Code: code, Name: name}, nil
}

// EnsureRole 是"给这个人单独加一个权限"背后的机制（§14.1.3）：幂等地
// 拿到一个角色，不存在就建。专属角色与自举角色都走这条路，不走
// CreateRole（后者拒绝 u: 前缀）。
func (r *Repo) EnsureRole(ctx context.Context, code, name string, isSystem bool) error {
	return besdk.WithTx(ctx, r.db, r.role, r.schema, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `
			INSERT INTO roles (code, name, is_system) VALUES ($1, $2, $3)
			ON CONFLICT (code) DO NOTHING`, code, name, isSystem)
		return wrap("ensure role", err)
	})
}

// EnsurePersonalRole 是 EnsureRole 在"给某个 sub 的专属角色"这个具体
// 场景上的薄封装——命名规则（u:<sub>）与展示名只在这一处定义。
func (r *Repo) EnsurePersonalRole(ctx context.Context, sub string) (roleCode string, err error) {
	code := personalRoleCode(sub)
	return code, r.EnsureRole(ctx, code, "专属角色："+sub, true)
}

// GetRole 查一个角色详情，含它当前挂着的权限键。
func (r *Repo) GetRole(ctx context.Context, code string) (*Role, error) {
	var role Role
	err := besdk.WithTx(ctx, r.db, r.role, r.schema, func(tx *sql.Tx) error {
		if err := tx.QueryRowContext(ctx,
			`SELECT code, name, is_system FROM roles WHERE code = $1`, code,
		).Scan(&role.Code, &role.Name, &role.IsSystem); err != nil {
			return err
		}
		keys, err := queryRolePermissionKeys(ctx, tx, code)
		if err != nil {
			return err
		}
		role.PermissionKeys = keys
		return nil
	})
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, wrap("查 role", err)
	}
	return &role, nil
}

// ListRoles 列管理员能管的角色——专属角色（is_system=true）不出现在这里，
// 那些只在"给某人授权"的界面里作为实现细节存在，管理员看不到（§14.1.3）。
// ⚠️ 这条判据只影响这个列表，不影响 ComputeBundle：bundle 的 roles 字段
// 必须包含全部角色（含 is_system），否则持有专属角色的人会静默失权
// （见 bundle.go 顶部注释）。
func (r *Repo) ListRoles(ctx context.Context) ([]*Role, error) {
	var roles []*Role
	err := besdk.WithTx(ctx, r.db, r.role, r.schema, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx,
			`SELECT code, name, is_system FROM roles WHERE is_system = false ORDER BY code`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var role Role
			if err := rows.Scan(&role.Code, &role.Name, &role.IsSystem); err != nil {
				return err
			}
			roles = append(roles, &role)
		}
		if err := rows.Err(); err != nil {
			return err
		}
		for _, role := range roles {
			keys, err := queryRolePermissionKeys(ctx, tx, role.Code)
			if err != nil {
				return err
			}
			role.PermissionKeys = keys
		}
		return nil
	})
	return roles, wrap("列 roles", err)
}

// DeleteRole 删一个角色——外键 ON DELETE CASCADE 会连带删掉
// role_permissions/user_roles 里指向它的行（设计上接受：删角色就是
// 要收回所有人通过它拿到的权限，无需再单独确认）。
func (r *Repo) DeleteRole(ctx context.Context, code string) error {
	return besdk.WithTx(ctx, r.db, r.role, r.schema, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `DELETE FROM roles WHERE code = $1`, code)
		if err != nil {
			return wrap("删 role", err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return err
		}
		if n == 0 {
			return ErrNotFound
		}
		return nil
	})
}

// GrantRolePermission 给角色勾一个权限键。幂等：已经勾过再勾一次不报错。
//
// ⚠️ 这条不写 role_changes、不影响任何人的 stale_since——角色内容变了
// 靠 bundle 的 roles 字段直接刷新（下一次轮询 ~15 秒内，所有持有该角色
// 的人自动拿到新内容），不需要让任何已签发的 token 失效（设计书
// §14.1.6：这是与"人的角色变了"完全不同的一档）。
func (r *Repo) GrantRolePermission(ctx context.Context, roleCode, permissionKey string) error {
	err := besdk.WithTx(ctx, r.db, r.role, r.schema, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `
			INSERT INTO role_permissions (role_code, permission_key) VALUES ($1, $2)
			ON CONFLICT (role_code, permission_key) DO NOTHING`, roleCode, permissionKey)
		return err
	})
	if err != nil {
		return mapConstraintErr(err, "角色或权限键不存在")
	}
	return nil
}

// RevokeRolePermission 取消角色的一个权限键。同样不触碰 stale_since。
func (r *Repo) RevokeRolePermission(ctx context.Context, roleCode, permissionKey string) error {
	return besdk.WithTx(ctx, r.db, r.role, r.schema, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx,
			`DELETE FROM role_permissions WHERE role_code = $1 AND permission_key = $2`,
			roleCode, permissionKey)
		return wrap("取消角色权限", err)
	})
}

func queryRolePermissionKeys(ctx context.Context, tx *sql.Tx, roleCode string) ([]string, error) {
	rows, err := tx.QueryContext(ctx,
		`SELECT permission_key FROM role_permissions WHERE role_code = $1 ORDER BY permission_key`, roleCode)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	keys := make([]string, 0)
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	return keys, rows.Err()
}
