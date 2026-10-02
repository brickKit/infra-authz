package repo

import (
	"context"
	"database/sql"

	besdk "github.com/brickKit/be-sdk-go"
)

// PermissionCatalogEntry 是权限键登记表（PERMISSION_CATALOG）的一行。
type PermissionCatalogEntry struct {
	Key            string
	Title          string
	Type           string
	OwnerComponent string
	Deprecated     string
}

// SyncPermissionCatalog 把目录里的每一条 upsert 进 permissions 表，
// 包括 deprecated 列：登记表是唯一的真相源，表只是它的镜像。
//
// ⚠️ 只 upsert，绝不删行——即使这次传进来的目录里缺了某个曾经存在的 key
// （组件被临时移出项目），本函数也不删那一行：已授给角色的键一删，
// role_permissions 跟着级联删除，持有者静默失权。废弃一个键是在登记表里
// 填 deprecated 列，键本身永远保留。
func (r *Repo) SyncPermissionCatalog(ctx context.Context, entries []PermissionCatalogEntry) error {
	return besdk.WithTx(ctx, r.db, r.role, r.schema, func(tx *sql.Tx) error {
		for _, e := range entries {
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO permissions (key, title, type, owner_component, deprecated)
				VALUES ($1, $2, $3, $4, $5)
				ON CONFLICT (key) DO UPDATE SET
					title = EXCLUDED.title,
					type = EXCLUDED.type,
					owner_component = EXCLUDED.owner_component,
					deprecated = EXCLUDED.deprecated,
					updated_at = now()`,
				e.Key, e.Title, e.Type, e.OwnerComponent, e.Deprecated); err != nil {
				return wrap("upsert permissions", err)
			}
		}
		return nil
	})
}

// PermissionExists 供上层在授权前校验 key 是否已知——比让调用方硬撞 FK
// 约束、再把 23503 翻译成 ErrNotFound 更直接。
func (r *Repo) PermissionExists(ctx context.Context, key string) (bool, error) {
	var exists bool
	err := besdk.WithTx(ctx, r.db, r.role, r.schema, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx,
			"SELECT EXISTS (SELECT 1 FROM permissions WHERE key = $1)", key).Scan(&exists)
	})
	return exists, wrap("查 permissions", err)
}
