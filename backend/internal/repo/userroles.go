package repo

import (
	"context"
	"database/sql"
	"time"

	besdk "github.com/brickKit/be-sdk-go"
)

// UserRole 是一个人当前持有的一条角色分配。
type UserRole struct {
	RoleCode  string
	ExpiresAt *time.Time // nil = 永不过期
}

// GrantUserRole 给 sub 授一个角色，可选 expires_at（nil = 永不过期）。
// 幂等：重复授予同一个角色、同一个到期时间是无操作。
//
// ⚠️ 这条会写 role_changes（changed=true 时），因为"人的角色变了"必须
// 让持有者的 JWT 尽快变 stale——他现有的 token 里没有这个新角色，靠
// bundle 刷新是等不到的，必须走 stale_since → 401 → 静默刷新这条路
// （设计书 §14.1.6）。changed 用"这次 upsert 是不是真的改变了什么"
// 判定：同一个角色、同一个到期时间再授一次是纯粹的无操作，不该也没
// 必要让人重新刷新一次 token。
func (r *Repo) GrantUserRole(ctx context.Context, sub, roleCode string, expiresAt *time.Time) error {
	return besdk.WithTx(ctx, r.db, r.role, r.schema, func(tx *sql.Tx) error {
		var changed bool
		err := tx.QueryRowContext(ctx, `
			INSERT INTO user_roles (sub, role_code, expires_at) VALUES ($1, $2, $3)
			ON CONFLICT (sub, role_code) DO UPDATE SET
				expires_at = EXCLUDED.expires_at, updated_at = now()
			WHERE user_roles.expires_at IS DISTINCT FROM EXCLUDED.expires_at
			RETURNING true`, sub, roleCode, expiresAt).Scan(&changed)
		if err == sql.ErrNoRows {
			return nil // 无操作：角色与到期时间都没变
		}
		if err != nil {
			return mapConstraintErr(err, "用户或角色不存在")
		}
		return recordRoleChange(ctx, tx, sub, &roleCode, "granted")
	})
}

// RevokeUserRole 撤销 sub 的一个角色。幂等：本来就没有这条分配也不报错
// （DELETE 天然幂等），但只有真的删掉了一行才写 role_changes——撤销一个
// 从未有过的角色不该制造虚假的 stale_since 噪音。
func (r *Repo) RevokeUserRole(ctx context.Context, sub, roleCode string) error {
	return besdk.WithTx(ctx, r.db, r.role, r.schema, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx,
			`DELETE FROM user_roles WHERE sub = $1 AND role_code = $2`, sub, roleCode)
		if err != nil {
			return wrap("撤销用户角色", err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return err
		}
		if n == 0 {
			return nil
		}
		return recordRoleChange(ctx, tx, sub, &roleCode, "revoked")
	})
}

// RevokeAllUserRoles 是"踢人"——一次性撤销 sub 的全部角色分配，只写一条
// role_changes（role_code 留空：这次影响的是这个人的全部角色，不是某一
// 个特定角色，见迁移里 role_changes.role_code 允许 NULL 的注释）。
//
// ⚠️ 这里只处理"人这边"（撤销角色分配），refresh token 的撤销是
// infra-iam-casdoor 的职责（登出链路的另一半，设计计划 §5）——两者合起来
// 才是完整的"踢人"（§14.1.6：踢人靠 stale_since 让他 401，再靠 refresh
// token 已撤销让他刷新失败，最终登出）。
func (r *Repo) RevokeAllUserRoles(ctx context.Context, sub string) error {
	return besdk.WithTx(ctx, r.db, r.role, r.schema, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `DELETE FROM user_roles WHERE sub = $1`, sub)
		if err != nil {
			return wrap("踢人：撤销全部角色", err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return err
		}
		if n == 0 {
			return nil
		}
		return recordRoleChange(ctx, tx, sub, nil, "kicked")
	})
}

// ListUserRoles 列 sub 当前有效的角色分配（已过期的不出现——那些对
// "他现在有什么"这个问题已经没有意义，历史追溯走 role_changes/审计事件，
// 不走这张表，设计计划 §7）。
func (r *Repo) ListUserRoles(ctx context.Context, sub string) ([]UserRole, error) {
	var out []UserRole
	err := besdk.WithTx(ctx, r.db, r.role, r.schema, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `
			SELECT role_code, expires_at FROM user_roles
			WHERE sub = $1 AND (expires_at IS NULL OR expires_at > now())
			ORDER BY role_code`, sub)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var ur UserRole
			if err := rows.Scan(&ur.RoleCode, &ur.ExpiresAt); err != nil {
				return err
			}
			out = append(out, ur)
		}
		return rows.Err()
	})
	return out, wrap("列用户角色", err)
}

// ActiveRoleCodes 是 ResolveClaims 用的：sub 当前全部未过期角色的 code
// 原始集合（不展开权限键——JWT 只带角色，权限键的展开在 be-sdk 里，
// 设计书 §14.1.5）。
func (r *Repo) ActiveRoleCodes(ctx context.Context, sub string) ([]string, error) {
	codes := make([]string, 0)
	err := besdk.WithTx(ctx, r.db, r.role, r.schema, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `
			SELECT role_code FROM user_roles
			WHERE sub = $1 AND (expires_at IS NULL OR expires_at > now())
			ORDER BY role_code`, sub)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var code string
			if err := rows.Scan(&code); err != nil {
				return err
			}
			codes = append(codes, code)
		}
		return rows.Err()
	})
	return codes, wrap("查用户当前角色", err)
}

// recordRoleChange 写一行 role_changes——stale_since 有界列表的来源
// （设计计划 §2、§14.1.6）。必须与触发它的那次 user_roles 变更在同一个
// 事务里提交，两者要么都成功要么都不发生。
func recordRoleChange(ctx context.Context, tx *sql.Tx, sub string, roleCode *string, changeType string) error {
	_, err := tx.ExecContext(ctx,
		`INSERT INTO role_changes (sub, role_code, change_type) VALUES ($1, $2, $3)`,
		sub, roleCode, changeType)
	return wrap("记录 role_changes", err)
}
