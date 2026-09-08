package repo

import (
	"context"
	"database/sql"
	"time"

	besdk "github.com/brickKit/be-sdk-go"
)

// Bundle 是 GET /authz/bundle 与 gRPC GetBundle 共用的下发内容（设计书
// §14.1.4）。JSON 标签决定了 REST 的线上格式，gRPC 侧在 grpc.go 里另外
// 转成 proto message——两边内容必须完全一致，来源都是这一个函数。
type Bundle struct {
	Roles      map[string][]string `json:"roles"`
	StaleSince map[string]int64    `json:"stale_since"`
}

// ComputeBundle 现算现返——roles/role_permissions 永远热、几百行恒小，
// stale_since 只看一个有界窗口，都不需要缓存或预计算（设计计划 §2）。
//
// ⚠️ roles 必须包含全部角色，含 is_system=true 的专属角色——持有
// u:<sub> 的用户的 JWT.roles[] 里就带着这个字符串，bundle 的 roles 里
// 找不到它，be-sdk 展开出来就是空集，静默失权、没有任何症状。这是本
// 组件测试覆盖优先级最高的一条断言。
//
// staleWindow 通常传 2× access token TTL（configSchema 的
// accessTokenTtlSeconds，设计书 §14.1.6）——调用方（service 层）负责算
// 这个窗口，本层只管拿窗口边界去查。
func (r *Repo) ComputeBundle(ctx context.Context, staleWindow time.Duration) (*Bundle, error) {
	b := &Bundle{Roles: map[string][]string{}, StaleSince: map[string]int64{}}
	err := besdk.WithTx(ctx, r.db, r.role, r.schema, func(tx *sql.Tx) error {
		if err := loadRolesInto(ctx, tx, b); err != nil {
			return err
		}
		return loadStaleSinceInto(ctx, tx, staleWindow, b)
	})
	return b, wrap("算 bundle", err)
}

// loadRolesInto 逐行 LEFT JOIN 而不是 array_agg——pgx 的 database/sql
// 通用接口不会自动把 text[] 解成 []string（Scan 到 *[]string 直接报
// "unsupported Scan"，真机测试实测踩出来的），逐行收集完全绕开这个
// 驱动细节，不需要再引入 pgtype 之类的辅助类型。
func loadRolesInto(ctx context.Context, tx *sql.Tx, b *Bundle) error {
	rows, err := tx.QueryContext(ctx, `
		SELECT r.code, rp.permission_key
		FROM roles r
		LEFT JOIN role_permissions rp ON rp.role_code = r.code
		ORDER BY r.code, rp.permission_key`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var code string
		var key sql.NullString
		if err := rows.Scan(&code, &key); err != nil {
			return err
		}
		if _, ok := b.Roles[code]; !ok {
			b.Roles[code] = []string{}
		}
		if key.Valid {
			b.Roles[code] = append(b.Roles[code], key.String)
		}
	}
	return rows.Err()
}

// loadStaleSinceInto 合并两个来源（设计书 §14.1.6、迁移文件注释）：
//  1. role_changes：granted/revoked/kicked 三种显式管理员动作
//  2. user_roles.expires_at：到期是纯粹的时间流逝，不需要任何人在到期
//     那一刻写一行——直接从落在窗口内、且已经过去的 expires_at 推导
//
// 每个 sub 取两个来源里更晚的那个时间戳。
func loadStaleSinceInto(ctx context.Context, tx *sql.Tx, staleWindow time.Duration, b *Bundle) error {
	windowStart := time.Now().Add(-staleWindow)
	rows, err := tx.QueryContext(ctx, `
		SELECT sub, MAX(ts) FROM (
			SELECT sub, changed_at AS ts FROM role_changes WHERE changed_at > $1
			UNION ALL
			SELECT sub, expires_at AS ts FROM user_roles
			WHERE expires_at IS NOT NULL AND expires_at <= now() AND expires_at > $1
		) t
		GROUP BY sub`, windowStart)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var sub string
		var ts time.Time
		if err := rows.Scan(&sub, &ts); err != nil {
			return err
		}
		b.StaleSince[sub] = ts.Unix()
	}
	return rows.Err()
}
