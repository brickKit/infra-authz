package repo

import (
	"context"
	"database/sql"

	besdk "github.com/brickKit/be-sdk-go"
)

// PermissionCatalogEntry 是权限键册的一条——be-ops 产出 9 经
// config.permissionCatalog 灌进来的（设计书 §14.1.2）。
type PermissionCatalogEntry struct {
	Key            string
	Title          string
	Type           string
	OwnerComponent string
}

// SyncPermissionCatalog 把目录里的每一条 upsert 进 permissions 表。
//
// ⚠️ 只增不改的规矩在这里体现为"只 upsert，绝不删行"——即使这次传进来
// 的目录里缺了某个曾经存在的 key（组件被临时移出装配），本函数也不会
// 删除那一行：废弃走 deprecated 墓碑列，是人工决定，不是本函数的职责
// （同 be-ops 的 registry/permissions.tsv 生成判据，registry/README.md）。
// deprecated 列本函数从不触碰。
func (r *Repo) SyncPermissionCatalog(ctx context.Context, entries []PermissionCatalogEntry) error {
	return besdk.WithTx(ctx, r.db, r.role, r.schema, func(tx *sql.Tx) error {
		for _, e := range entries {
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO permissions (key, title, type, owner_component)
				VALUES ($1, $2, $3, $4)
				ON CONFLICT (key) DO UPDATE SET
					title = EXCLUDED.title,
					type = EXCLUDED.type,
					owner_component = EXCLUDED.owner_component,
					updated_at = now()`,
				e.Key, e.Title, e.Type, e.OwnerComponent); err != nil {
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
