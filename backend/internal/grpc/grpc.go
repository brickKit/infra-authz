// Package grpc 实现 infra.authz.v1.AuthzService——内部 gRPC 面（设计
// 计划 §3）。HTTP 与 gRPC 共用同一个 service.Service，业务逻辑只写一遍。
package grpc

import (
	"context"
	"errors"

	authzv1 "github.com/brickKit/infra-authz/gen/infra/authz/v1"

	"github.com/brickKit/infra-authz/v2/backend/internal/repo"
	"github.com/brickKit/infra-authz/v2/backend/internal/service"
)

type server struct {
	authzv1.UnimplementedAuthzServiceServer
	svc *service.Service
}

func New(svc *service.Service) authzv1.AuthzServiceServer {
	return &server{svc: svc}
}

func toProtoRole(r *repo.Role) *authzv1.Role {
	return &authzv1.Role{
		Code: r.Code, Name: r.Name, IsSystem: r.IsSystem, PermissionKeys: r.PermissionKeys,
	}
}

// BatchGetRoles 是按一批 code 读角色的批量接口（调用方不必逐个调）。
// 查不到的 code 直接在结果里省略（batchGet 惯例），不报错——调用方按 code
// 对不上判断哪些缺失；别的错误（数据库不可用）照常返回，否则调用方会把
// "库挂了"当成"这些角色都不存在"。
func (s *server) BatchGetRoles(ctx context.Context, req *authzv1.BatchGetRolesRequest) (*authzv1.BatchGetRolesResponse, error) {
	roles := make([]*authzv1.Role, 0, len(req.Codes))
	for _, code := range req.Codes {
		r, err := s.svc.GetRole(ctx, code)
		if errors.Is(err, repo.ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, service.ToStatus(err)
		}
		roles = append(roles, toProtoRole(r))
	}
	return &authzv1.BatchGetRolesResponse{Roles: roles}, nil
}

// ResolveClaims 给 infra-iam-casdoor：sub -> roles[]/dept_path/org_id。
// ⚠️ 登录与刷新时各调一次，绝不缓存（设计计划 §4）。
func (s *server) ResolveClaims(ctx context.Context, req *authzv1.ResolveClaimsRequest) (*authzv1.ResolveClaimsResponse, error) {
	roles, deptPath, orgID, err := s.svc.ResolveClaims(ctx, req.Sub)
	if err != nil {
		return nil, service.ToStatus(err)
	}
	return &authzv1.ResolveClaimsResponse{Roles: roles, DeptPath: deptPath, OrgId: orgID}, nil
}

// GetBundle 是 gRPC 版的策略下发，内容与 GET /authz/bundle 完全一致
// （同一个 service.GetBundle）。
func (s *server) GetBundle(ctx context.Context, _ *authzv1.GetBundleRequest) (*authzv1.Bundle, error) {
	b, err := s.svc.GetBundle(ctx)
	if err != nil {
		return nil, service.ToStatus(err)
	}
	roles := make(map[string]*authzv1.RolePermissionKeys, len(b.Roles))
	for code, keys := range b.Roles {
		roles[code] = &authzv1.RolePermissionKeys{Keys: keys}
	}
	return &authzv1.Bundle{Roles: roles, StaleSince: b.StaleSince}, nil
}
