// Package service 是 infra-authz 的业务编排层——HTTP 与 gRPC 两个对外
// 面共用同一份逻辑，业务代码只写一遍（同 erp-finance 的分层判据）。
//
// 大部分不变量已经在 repo 层用事务与约束守住（幂等 upsert、role_changes
// 与触发它的变更同一事务提交）；这一层负责的是跨越单条 repo 方法的
// 编排（如"给人加一个权限"要建专属角色 + 挂权限键 + 授角色三步）、
// 把 configSchema 的原始配置翻译成 repo 认得的类型、以及 ETag 计算。
package service

import (
	"context"
	"time"

	"github.com/brickKit/infra-authz/backend/internal/repo"
)

type Service struct {
	repo           *repo.Repo
	accessTokenTTL time.Duration
	defaultOrgID   string
}

func New(r *repo.Repo, accessTokenTTL time.Duration, defaultOrgID string) *Service {
	return &Service{repo: r, accessTokenTTL: accessTokenTTL, defaultOrgID: defaultOrgID}
}

// SyncPermissionCatalog 解析 config.permissionCatalog 的原始字符串并
// upsert 进 permissions 表（设计书 §14.1.2）。空字符串是合法的启动态
// （还没有任何组件声明权限键），直接跳过，不是错误。
func (s *Service) SyncPermissionCatalog(ctx context.Context, raw string) error {
	entries, err := ParsePermissionCatalog(raw)
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		return nil
	}
	repoEntries := make([]repo.PermissionCatalogEntry, len(entries))
	for i, e := range entries {
		repoEntries[i] = repo.PermissionCatalogEntry(e)
	}
	return s.repo.SyncPermissionCatalog(ctx, repoEntries)
}

// EnsureBootstrapAdmin 幂等地把 authz_admin 角色授予 configSchema 里配置
// 的 bootstrapAdminSub（Task 4 设计决策，解决"第一个管理员怎么来"的
// 鸡生蛋问题，见 README「自举」一节）。sub 为空表示还没配置，跳过——
// 不是错误，客户可能选择完全手工建第一个管理员。
func (s *Service) EnsureBootstrapAdmin(ctx context.Context, sub string) error {
	if sub == "" {
		return nil
	}
	return s.repo.GrantUserRole(ctx, sub, "authz_admin", nil)
}

// GetBundle 现算现返——staleWindow = 2× access token TTL（§14.1.6）。
func (s *Service) GetBundle(ctx context.Context) (*repo.Bundle, error) {
	return s.repo.ComputeBundle(ctx, 2*s.accessTokenTTL)
}

// MyPermissions 展开一个人当前全部角色的权限键并集（纯并集，无 Deny，
// 设计书 §14.1.3）——GET /api/me/permissions 与 be-sdk 判定链的第 3 步
// 是同一个"并集展开"逻辑，这里独立实现是因为本组件的管理 API 不通过
// 轮询自己的 bundle 来回答"我自己有什么权限"这种自省式问题，直接查
// 数据库更直接、也不必等 15 秒的轮询周期。
func (s *Service) MyPermissions(ctx context.Context, sub string) ([]string, error) {
	codes, err := s.repo.ActiveRoleCodes(ctx, sub)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var keys []string
	for _, code := range codes {
		role, err := s.repo.GetRole(ctx, code)
		if err != nil {
			continue // 角色在查询瞬间被删掉是良性竞态，跳过而不是让整个请求失败
		}
		for _, k := range role.PermissionKeys {
			if !seen[k] {
				seen[k] = true
				keys = append(keys, k)
			}
		}
	}
	return keys, nil
}

// ResolveClaims 给 infra-iam-casdoor：sub -> roles[]/dept_path/org_id
// （设计书 §3、§4）。⚠️ 登录与刷新时各调一次，绝不缓存——这是两个
// token 架构下 stale_since 能"写完就立刻生效"的前提（infra-iam-casdoor
// 设计计划 §3.2）。
func (s *Service) ResolveClaims(ctx context.Context, sub string) (roles []string, deptPath string, orgID string, err error) {
	roles, err = s.repo.ActiveRoleCodes(ctx, sub)
	if err != nil {
		return nil, "", "", err
	}
	deptPath, err = s.repo.DeptPathFor(ctx, sub)
	if err != nil {
		return nil, "", "", err
	}
	return roles, deptPath, s.defaultOrgID, nil
}

// GrantUserPermission 是"给这个人单独加一个权限"的编排（设计书
// §14.1.3）：确保专属角色 u:<sub> 存在、给它挂权限键、把它授给这个人——
// 三步都是幂等的，第三步失败会让第一、二步的效果留下（专属角色多了
// 一个权限键但暂时没人持有），这在设计上可以接受：下次重试同一个调用
// 会把第三步补上，不会产生"半成品"角色以外的副作用。
func (s *Service) GrantUserPermission(ctx context.Context, sub, permissionKey string) error {
	roleCode, err := s.repo.EnsurePersonalRole(ctx, sub)
	if err != nil {
		return err
	}
	if err := s.repo.GrantRolePermission(ctx, roleCode, permissionKey); err != nil {
		return err
	}
	return s.repo.GrantUserRole(ctx, sub, roleCode, nil)
}

// ── 角色 CRUD 与分配——薄封装，编排逻辑都已经在 repo 层用事务守住，
// 这里只是让 http/grpc 两层不用直接依赖 repo.Repo（同 erp-finance 的
// 分层判据：业务代码只认 Service，Repo 是它的实现细节）。────────────

func (s *Service) CreateRole(ctx context.Context, code, name string) (*repo.Role, error) {
	return s.repo.CreateRole(ctx, code, name)
}

func (s *Service) GetRole(ctx context.Context, code string) (*repo.Role, error) {
	return s.repo.GetRole(ctx, code)
}

func (s *Service) ListRoles(ctx context.Context) ([]*repo.Role, error) {
	return s.repo.ListRoles(ctx)
}

func (s *Service) DeleteRole(ctx context.Context, code string) error {
	return s.repo.DeleteRole(ctx, code)
}

func (s *Service) GrantRolePermission(ctx context.Context, roleCode, permissionKey string) error {
	return s.repo.GrantRolePermission(ctx, roleCode, permissionKey)
}

func (s *Service) RevokeRolePermission(ctx context.Context, roleCode, permissionKey string) error {
	return s.repo.RevokeRolePermission(ctx, roleCode, permissionKey)
}

func (s *Service) GrantUserRole(ctx context.Context, sub, roleCode string, expiresAt *time.Time) error {
	return s.repo.GrantUserRole(ctx, sub, roleCode, expiresAt)
}

func (s *Service) RevokeUserRole(ctx context.Context, sub, roleCode string) error {
	return s.repo.RevokeUserRole(ctx, sub, roleCode)
}

func (s *Service) RevokeAllUserRoles(ctx context.Context, sub string) error {
	return s.repo.RevokeAllUserRoles(ctx, sub)
}

func (s *Service) ListUserRoles(ctx context.Context, sub string) ([]repo.UserRole, error) {
	return s.repo.ListUserRoles(ctx, sub)
}

func (s *Service) CreateDepartment(ctx context.Context, name string, parentID *int64) (*repo.Department, error) {
	return s.repo.CreateDepartment(ctx, name, parentID)
}

func (s *Service) ListDepartments(ctx context.Context) ([]*repo.Department, error) {
	return s.repo.ListDepartments(ctx)
}

func (s *Service) AssignUserDepartment(ctx context.Context, sub string, departmentID int64) error {
	return s.repo.AssignUserDepartment(ctx, sub, departmentID)
}
