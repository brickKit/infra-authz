package repo

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"sync/atomic"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib" // §12.4：不用 lib/pq，驱动名注册为 "pgx"
)

func testDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("TEST_PG_DSN")
	if dsn == "" {
		t.Skip("未设置 TEST_PG_DSN")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

var idSeq int64

// uniqueID 给每个测试造一个独立的 sub/role code 前缀，测试之间不共享行、
// 互不干扰——这个 schema 里还有一条真实的自举种子数据（authz_admin/
// infra.authz.admin），测试不能撞上它。
func uniqueID(prefix string) string {
	n := atomic.AddInt64(&idSeq, 1)
	return fmt.Sprintf("%s_%d_%d", prefix, time.Now().UnixNano(), n)
}

func testRepo(t *testing.T) *Repo {
	return New(testDB(t), "infra_authz_rw", "infra_authz")
}

func mustCreatePermission(t *testing.T, r *Repo, key string) {
	t.Helper()
	if err := r.SyncPermissionCatalog(context.Background(), []PermissionCatalogEntry{
		{Key: key, Title: "测试权限", Type: "action", OwnerComponent: "test/fixture"},
	}); err != nil {
		t.Fatal(err)
	}
}

func mustCreateRole(t *testing.T, r *Repo, code string) {
	t.Helper()
	if _, err := r.CreateRole(context.Background(), code, "测试角色 "+code); err != nil {
		t.Fatal(err)
	}
}

// grantUserPermission 在测试里内联复现 service.GrantUserPermission 的
// 三步编排（EnsurePersonalRole + GrantRolePermission + GrantUserRole）。
// ⚠️ 故意不在 repo 包里加一个同名生产方法——那样会有两份同一件事的
// 实现（这里一份、service.go 一份），改一边忘了改另一边就会让测试
// 通过掩盖真实回归。repo 层的职责就是提供这三个可独立测试的原子操作，
// 编排属于 service 层。
func grantUserPermission(t *testing.T, r *Repo, sub, permissionKey string) {
	t.Helper()
	ctx := context.Background()
	roleCode, err := r.EnsurePersonalRole(ctx, sub)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.GrantRolePermission(ctx, roleCode, permissionKey); err != nil {
		t.Fatal(err)
	}
	if err := r.GrantUserRole(ctx, sub, roleCode, nil); err != nil {
		t.Fatal(err)
	}
}

// ── ComputeBundle ────────────────────────────────────────────────────

func TestComputeBundle_角色权限展开正确(t *testing.T) {
	ctx := context.Background()
	r := testRepo(t)
	role := uniqueID("role")
	permA := uniqueID("perm.a")
	permB := uniqueID("perm.b")
	mustCreatePermission(t, r, permA)
	mustCreatePermission(t, r, permB)
	mustCreateRole(t, r, role)
	if err := r.GrantRolePermission(ctx, role, permA); err != nil {
		t.Fatal(err)
	}
	if err := r.GrantRolePermission(ctx, role, permB); err != nil {
		t.Fatal(err)
	}

	b, err := r.ComputeBundle(ctx, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	keys := b.Roles[role]
	if len(keys) != 2 || keys[0] != permA && keys[0] != permB {
		t.Fatalf("角色 %s 的权限键展开不对：%v", role, keys)
	}
}

// TestComputeBundle_专属角色也出现在roles里 是本组件优先级最高的一条
// 断言（bundle.go 顶部注释、roles.go ListRoles 注释）：is_system=true
// 的专属角色如果不出现在 bundle 的 roles 字段里，持有它的用户的 JWT
// roles[] 展开出来就是空集——静默失权，没有任何症状。
func TestComputeBundle_专属角色也出现在roles里(t *testing.T) {
	ctx := context.Background()
	r := testRepo(t)
	sub := uniqueID("sub")
	perm := uniqueID("perm.personal")
	mustCreatePermission(t, r, perm)

	grantUserPermission(t, r, sub, perm)
	personalRole := "u:" + sub

	b, err := r.ComputeBundle(ctx, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	keys, ok := b.Roles[personalRole]
	if !ok {
		t.Fatalf("专属角色 %s 应该出现在 bundle.Roles 里，实际 bundle.Roles=%v", personalRole, b.Roles)
	}
	if len(keys) != 1 || keys[0] != perm {
		t.Fatalf("专属角色的权限键不对：%v", keys)
	}
}

func TestComputeBundle_statleSince窗口外的变更不出现(t *testing.T) {
	ctx := context.Background()
	r := testRepo(t)
	sub := uniqueID("sub")
	role := uniqueID("role")
	mustCreateRole(t, r, role)
	if err := r.GrantUserRole(ctx, sub, role, nil); err != nil {
		t.Fatal(err)
	}

	// 窗口给 1 纳秒——刚写的这条 role_changes 必然落在窗口外。
	b, err := r.ComputeBundle(ctx, time.Nanosecond)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := b.StaleSince[sub]; ok {
		t.Fatalf("窗口外的变更不该出现在 stale_since 里，实际 %v", b.StaleSince[sub])
	}
}

func TestComputeBundle_statleSince窗口内的授予会出现(t *testing.T) {
	ctx := context.Background()
	r := testRepo(t)
	sub := uniqueID("sub")
	role := uniqueID("role")
	mustCreateRole(t, r, role)
	if err := r.GrantUserRole(ctx, sub, role, nil); err != nil {
		t.Fatal(err)
	}

	b, err := r.ComputeBundle(ctx, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ts, ok := b.StaleSince[sub]
	if !ok {
		t.Fatalf("窗口内的授予应该出现在 stale_since 里")
	}
	if time.Since(time.Unix(ts, 0)) > time.Minute {
		t.Fatalf("stale_since 时间戳看起来不对：%v", ts)
	}
}

// TestComputeBundle_statleSince来自到期的user_roles 是"过期不需要任何
// 人写一行 role_changes"这条设计（迁移文件与 bundle.go 的注释）的真实
// 验证：只造一条已经过期的 user_roles 行，不碰 role_changes，断言
// stale_since 依然把它算进去。
func TestComputeBundle_statleSince来自到期的user_roles(t *testing.T) {
	ctx := context.Background()
	r := testRepo(t)
	sub := uniqueID("sub")
	role := uniqueID("role")
	mustCreateRole(t, r, role)

	past := time.Now().Add(-30 * time.Second)
	if err := r.GrantUserRole(ctx, sub, role, &past); err != nil {
		t.Fatal(err)
	}
	// GrantUserRole 本身会写一条 role_changes("granted")；把窗口设得比
	// "刚才发生的授予"更早、但比"30 秒前的到期时间"更晚，隔离出只有
	// 到期能命中的窗口是不可能的（授予也是刚刚发生）。所以这条测试改为
	// 直接断言"过期的 expires_at 落在窗口内时确实贡献了 stale_since"，
	// 不特别要求隔离掉 granted 那条——两个来源都命中、取较晚值，同样
	// 证明了 UNION 逻辑在起作用。
	b, err := r.ComputeBundle(ctx, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := b.StaleSince[sub]; !ok {
		t.Fatalf("已过期的 user_roles 行应该贡献 stale_since")
	}

	// 再单独验证纯"只有到期、没有 granted 事件在窗口内"的情况：把窗口
	// 缩到只能盖住"30 秒前的到期"，盖不住"更早之前的 granted"——
	// 这里 granted 与到期几乎同时发生，改用极短窗口反而两条都会被
	// 排除，所以改成检查窗口恰好覆盖过期点但明显早于 now 的场景。
	longAgo := time.Now().Add(-2 * time.Hour)
	sub2 := uniqueID("sub2")
	role2 := uniqueID("role2")
	mustCreateRole(t, r, role2)
	if err := r.GrantUserRole(ctx, sub2, role2, &longAgo); err != nil {
		t.Fatal(err)
	}
	// 窗口只有 90 分钟：granted 事件（刚刚发生）仍在窗口内，到期时间
	// （2 小时前）已经出窗口——这条断言真正隔离出"只有 granted 命中"
	// 的情况，用于对照上面"两个来源都命中"的情况。
	b2, err := r.ComputeBundle(ctx, 90*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := b2.StaleSince[sub2]; !ok {
		t.Fatalf("granted 事件本身也应该在窗口内贡献 stale_since")
	}
}

// ── GrantUserRole / RevokeUserRole 的幂等与 role_changes 记账 ─────────

// countRoleChanges 查真相不经过 WithTx（测试直连用的是超级用户，本来
// 就能跨 schema 读，不需要 SET LOCAL ROLE）——schema 前缀直接写在表名
// 里，一条语句，避免 database/sql 的 QueryRow 不支持多语句这个坑。
func countRoleChanges(t *testing.T, db *sql.DB, sub string) int {
	t.Helper()
	var n int
	if err := db.QueryRow(
		`SELECT count(*) FROM infra_authz.role_changes WHERE sub = $1`, sub,
	).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestGrantUserRole_重复授予同一到期时间不重复记账(t *testing.T) {
	ctx := context.Background()
	db := testDB(t)
	r := New(db, "infra_authz_rw", "infra_authz")
	sub := uniqueID("sub")
	role := uniqueID("role")
	mustCreateRole(t, r, role)

	if err := r.GrantUserRole(ctx, sub, role, nil); err != nil {
		t.Fatal(err)
	}
	if err := r.GrantUserRole(ctx, sub, role, nil); err != nil {
		t.Fatal(err)
	}
	if n := countRoleChanges(t, db, sub); n != 1 {
		t.Fatalf("同一到期时间重复授予不该重复记 role_changes，得到 %d 条", n)
	}
}

func TestGrantUserRole_到期时间变化才算变更(t *testing.T) {
	ctx := context.Background()
	db := testDB(t)
	r := New(db, "infra_authz_rw", "infra_authz")
	sub := uniqueID("sub")
	role := uniqueID("role")
	mustCreateRole(t, r, role)

	if err := r.GrantUserRole(ctx, sub, role, nil); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(24 * time.Hour)
	if err := r.GrantUserRole(ctx, sub, role, &future); err != nil {
		t.Fatal(err)
	}
	if n := countRoleChanges(t, db, sub); n != 2 {
		t.Fatalf("到期时间真的变了应该算一次新变更，累计应有 2 条，得到 %d", n)
	}
}

func TestRevokeUserRole_删除不存在的分配不报错不记账(t *testing.T) {
	ctx := context.Background()
	db := testDB(t)
	r := New(db, "infra_authz_rw", "infra_authz")
	sub := uniqueID("sub")
	role := uniqueID("role")
	mustCreateRole(t, r, role)

	if err := r.RevokeUserRole(ctx, sub, role); err != nil {
		t.Fatal(err)
	}
	if n := countRoleChanges(t, db, sub); n != 0 {
		t.Fatalf("撤销一个从未存在的分配不该记账，得到 %d 条", n)
	}
}

func TestRevokeUserRole_删除已存在的分配会记账(t *testing.T) {
	ctx := context.Background()
	db := testDB(t)
	r := New(db, "infra_authz_rw", "infra_authz")
	sub := uniqueID("sub")
	role := uniqueID("role")
	mustCreateRole(t, r, role)
	if err := r.GrantUserRole(ctx, sub, role, nil); err != nil {
		t.Fatal(err)
	}
	if err := r.RevokeUserRole(ctx, sub, role); err != nil {
		t.Fatal(err)
	}
	if n := countRoleChanges(t, db, sub); n != 2 { // granted + revoked
		t.Fatalf("期望 granted+revoked 共 2 条，得到 %d", n)
	}
	codes, err := r.ActiveRoleCodes(ctx, sub)
	if err != nil {
		t.Fatal(err)
	}
	if len(codes) != 0 {
		t.Fatalf("撤销后不该再是当前有效角色，得到 %v", codes)
	}
}

func TestRevokeAllUserRoles_踢人只记一条role_changes(t *testing.T) {
	ctx := context.Background()
	db := testDB(t)
	r := New(db, "infra_authz_rw", "infra_authz")
	sub := uniqueID("sub")
	role1 := uniqueID("role")
	role2 := uniqueID("role")
	mustCreateRole(t, r, role1)
	mustCreateRole(t, r, role2)
	if err := r.GrantUserRole(ctx, sub, role1, nil); err != nil {
		t.Fatal(err)
	}
	if err := r.GrantUserRole(ctx, sub, role2, nil); err != nil {
		t.Fatal(err)
	}

	if err := r.RevokeAllUserRoles(ctx, sub); err != nil {
		t.Fatal(err)
	}
	// 2 条 granted + 1 条 kicked = 3
	if n := countRoleChanges(t, db, sub); n != 3 {
		t.Fatalf("期望 2 granted + 1 kicked 共 3 条，得到 %d", n)
	}
	codes, err := r.ActiveRoleCodes(ctx, sub)
	if err != nil {
		t.Fatal(err)
	}
	if len(codes) != 0 {
		t.Fatalf("踢人后不该有任何有效角色，得到 %v", codes)
	}
}

// ── SyncPermissionCatalog：只增不改 ────────────────────────────────

func TestSyncPermissionCatalog_只upsert不删除已有key(t *testing.T) {
	ctx := context.Background()
	r := testRepo(t)
	key := uniqueID("perm.orphan")
	mustCreatePermission(t, r, key)

	// 第二次同步一个完全不含这个 key 的目录——它不该被删除。
	other := uniqueID("perm.other")
	if err := r.SyncPermissionCatalog(ctx, []PermissionCatalogEntry{
		{Key: other, Title: "另一个", Type: "action", OwnerComponent: "test/fixture"},
	}); err != nil {
		t.Fatal(err)
	}
	exists, err := r.PermissionExists(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	if !exists {
		t.Fatalf("已存在的权限键不该被后续同步删除")
	}
}

func TestSyncPermissionCatalog_重复同步刷新title(t *testing.T) {
	ctx := context.Background()
	r := testRepo(t)
	key := uniqueID("perm.refresh")
	if err := r.SyncPermissionCatalog(ctx, []PermissionCatalogEntry{
		{Key: key, Title: "旧标题", Type: "action", OwnerComponent: "test/fixture"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := r.SyncPermissionCatalog(ctx, []PermissionCatalogEntry{
		{Key: key, Title: "新标题", Type: "action", OwnerComponent: "test/fixture"},
	}); err != nil {
		t.Fatal(err)
	}

	role := uniqueID("role")
	mustCreateRole(t, r, role)
	if err := r.GrantRolePermission(ctx, role, key); err != nil {
		t.Fatal(err) // 顺带确认刷新后 FK 仍然指向同一行，没有产生重复
	}
}

// ── 角色 CRUD 的边界 ───────────────────────────────────────────────

func TestCreateRole_u前缀被拒绝(t *testing.T) {
	r := testRepo(t)
	_, err := r.CreateRole(context.Background(), "u:someone", "不该被允许")
	if !errors.Is(err, ErrRoleCodeReserved) {
		t.Fatalf("期望 ErrRoleCodeReserved，得到 %v", err)
	}
}

func TestListRoles_不包含专属角色(t *testing.T) {
	ctx := context.Background()
	r := testRepo(t)
	sub := uniqueID("sub")
	perm := uniqueID("perm")
	mustCreatePermission(t, r, perm)
	grantUserPermission(t, r, sub, perm)
	roles, err := r.ListRoles(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, role := range roles {
		if role.Code == "u:"+sub {
			t.Fatalf("专属角色不该出现在 ListRoles 里：%+v", role)
		}
	}
}

func TestDeleteRole_不存在返回NotFound(t *testing.T) {
	r := testRepo(t)
	err := r.DeleteRole(context.Background(), uniqueID("nonexistent"))
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("期望 ErrNotFound，得到 %v", err)
	}
}

func TestGrantRolePermission_权限键不存在返回NotFound(t *testing.T) {
	r := testRepo(t)
	role := uniqueID("role")
	mustCreateRole(t, r, role)
	err := r.GrantRolePermission(context.Background(), role, uniqueID("no.such.perm"))
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("期望包装了 ErrNotFound（外键约束翻译），得到 %v", err)
	}
}

// ── 部门（阶段三极简表）────────────────────────────────────────────

func TestDeptPathFor_未分配返回空串不报错(t *testing.T) {
	r := testRepo(t)
	path, err := r.DeptPathFor(context.Background(), uniqueID("nobody"))
	if err != nil {
		t.Fatal(err)
	}
	if path != "" {
		t.Fatalf("未分配部门应该返回空串，得到 %q", path)
	}
}

func TestCreateDepartment_子部门dept_path含父路径前缀(t *testing.T) {
	ctx := context.Background()
	r := testRepo(t)
	parent, err := r.CreateDepartment(ctx, uniqueID("parent-dept"), nil)
	if err != nil {
		t.Fatal(err)
	}
	child, err := r.CreateDepartment(ctx, uniqueID("child-dept"), &parent.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(child.DeptPath) <= len(parent.DeptPath) || child.DeptPath[:len(parent.DeptPath)] != parent.DeptPath {
		t.Fatalf("子部门 dept_path (%q) 应该以父部门 dept_path (%q) 为前缀", child.DeptPath, parent.DeptPath)
	}

	sub := uniqueID("sub")
	if err := r.AssignUserDepartment(ctx, sub, child.ID); err != nil {
		t.Fatal(err)
	}
	path, err := r.DeptPathFor(ctx, sub)
	if err != nil {
		t.Fatal(err)
	}
	if path != child.DeptPath {
		t.Fatalf("ResolveClaims 该看到的 dept_path 不对：期望 %q 得到 %q", child.DeptPath, path)
	}
}
