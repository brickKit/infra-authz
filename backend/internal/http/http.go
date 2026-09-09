// Package http 是 infra-authz 的 REST 面。⚠️ 路径形状与其他组件不同——
// 不走 /{domain}/{name}/** 前缀，见 contracts/authz.openapi.yaml 顶部
// 注释与设计计划 §3。
package http

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	besdk "github.com/brickKit/be-sdk-go"
	"github.com/brickKit/infra-authz/backend/internal/repo"
	"github.com/brickKit/infra-authz/backend/internal/service"
)

// RegisterRoutes 挂载全部路由。
//
// 阶段三 Task 6：权限键从阶段二的 besdk.Public 换成真实键——
//   - /authz/bundle 永久保持 Public——它本身就是其他组件判权限的数据
//     来源，不能靠它自己判权限（鸡生蛋），且不进 edge_routes、不经网关
//     暴露（assembly.yaml 注释、设计计划 §3）。
//   - /api/me/permissions 换成 besdk.Authenticated（Task 4/5 发现并补
//     上的哨兵值）——任何登录用户都该能查自己的权限，不需要具体权限键。
//   - /api/admin/** 全部换成 infra.authz.admin——本组件自吃自己下发的
//     bundle（README「自我鉴权」一节），不是需要绕开的特例。
func RegisterRoutes(eng *gin.Engine, svc *service.Service) {
	besdk.GET(eng, "/authz/bundle", besdk.Public, getBundleHandler(svc))

	besdk.GET(eng, "/api/me/permissions", besdk.Authenticated, myPermissionsHandler(svc))

	g := eng.Group("/api/admin")
	besdk.GET(g, "/roles", "infra.authz.admin", listRolesHandler(svc))
	besdk.POST(g, "/roles", "infra.authz.admin", createRoleHandler(svc))
	besdk.GET(g, "/roles/:code", "infra.authz.admin", getRoleHandler(svc))
	besdk.DELETE(g, "/roles/:code", "infra.authz.admin", deleteRoleHandler(svc))
	besdk.POST(g, "/roles/:code/permissions", "infra.authz.admin", grantRolePermissionHandler(svc))
	besdk.DELETE(g, "/roles/:code/permissions/:key", "infra.authz.admin", revokeRolePermissionHandler(svc))

	besdk.GET(g, "/users/:sub/roles", "infra.authz.admin", listUserRolesHandler(svc))
	besdk.POST(g, "/users/:sub/roles", "infra.authz.admin", grantUserRoleHandler(svc))
	besdk.DELETE(g, "/users/:sub/roles/:code", "infra.authz.admin", revokeUserRoleHandler(svc))
	besdk.POST(g, "/users/:sub/permissions", "infra.authz.admin", grantUserPermissionHandler(svc))
	besdk.POST(g, "/users/:sub/revoke", "infra.authz.admin", revokeAllUserRolesHandler(svc))
	besdk.POST(g, "/users/:sub/department", "infra.authz.admin", assignUserDepartmentHandler(svc))

	besdk.GET(g, "/departments", "infra.authz.admin", listDepartmentsHandler(svc))
	besdk.POST(g, "/departments", "infra.authz.admin", createDepartmentHandler(svc))
}

func getBundleHandler(svc *service.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		bundle, err := svc.GetBundle(c.Request.Context())
		if err != nil {
			_ = c.Error(service.ToStatus(err))
			return
		}
		body, err := json.Marshal(bundle)
		if err != nil {
			_ = c.Error(err)
			return
		}
		sum := sha256.Sum256(body)
		etag := `"` + hex.EncodeToString(sum[:]) + `"`
		if c.GetHeader("If-None-Match") == etag {
			c.Header("ETag", etag)
			c.Status(http.StatusNotModified)
			return
		}
		c.Header("ETag", etag)
		c.Data(http.StatusOK, "application/json", body)
	}
}

// myPermissionsHandler：sub 从已验签 JWT 的 Claims 取（besdk.ScopeOf(ctx).Owner
// 就是 claims.Sub，同 erp-inventory/erp-finance 拿调用者身份的既有判据）
// ——阶段三 Task 4 遗留的临时 X-Authz-Debug-Sub header 到这里正式退役。
// besdk.Authenticated 已经保证走到这里时 ctx 里一定有 Claims，不需要
// 再判断"取不到就当未登录"这种分支。
func myPermissionsHandler(svc *service.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		sub := besdk.ScopeOf(c.Request.Context()).Owner
		keys, err := svc.MyPermissions(c.Request.Context(), sub)
		if err != nil {
			_ = c.Error(service.ToStatus(err))
			return
		}
		if keys == nil {
			keys = []string{}
		}
		c.JSON(http.StatusOK, gin.H{"keys": keys})
	}
}

func roleDTO(r *repo.Role) gin.H {
	keys := r.PermissionKeys
	if keys == nil {
		keys = []string{}
	}
	return gin.H{"code": r.Code, "name": r.Name, "is_system": r.IsSystem, "permission_keys": keys}
}

func listRolesHandler(svc *service.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		roles, err := svc.ListRoles(c.Request.Context())
		if err != nil {
			_ = c.Error(service.ToStatus(err))
			return
		}
		dtos := make([]gin.H, 0, len(roles))
		for _, r := range roles {
			dtos = append(dtos, roleDTO(r))
		}
		c.JSON(http.StatusOK, gin.H{"roles": dtos})
	}
}

type createRoleRequest struct {
	Code string `json:"code" binding:"required"`
	Name string `json:"name" binding:"required"`
}

func createRoleHandler(svc *service.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req createRoleRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		role, err := svc.CreateRole(c.Request.Context(), req.Code, req.Name)
		if err != nil {
			_ = c.Error(service.ToStatus(err))
			return
		}
		c.JSON(http.StatusOK, roleDTO(role))
	}
}

func getRoleHandler(svc *service.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		role, err := svc.GetRole(c.Request.Context(), c.Param("code"))
		if err != nil {
			_ = c.Error(service.ToStatus(err))
			return
		}
		c.JSON(http.StatusOK, roleDTO(role))
	}
}

func deleteRoleHandler(svc *service.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		if err := svc.DeleteRole(c.Request.Context(), c.Param("code")); err != nil {
			_ = c.Error(service.ToStatus(err))
			return
		}
		c.Status(http.StatusOK)
	}
}

type grantRolePermissionRequest struct {
	PermissionKey string `json:"permission_key" binding:"required"`
}

func grantRolePermissionHandler(svc *service.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req grantRolePermissionRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		if err := svc.GrantRolePermission(c.Request.Context(), c.Param("code"), req.PermissionKey); err != nil {
			_ = c.Error(service.ToStatus(err))
			return
		}
		c.Status(http.StatusOK)
	}
}

func revokeRolePermissionHandler(svc *service.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		err := svc.RevokeRolePermission(c.Request.Context(), c.Param("code"), c.Param("key"))
		if err != nil {
			_ = c.Error(service.ToStatus(err))
			return
		}
		c.Status(http.StatusOK)
	}
}

func listUserRolesHandler(svc *service.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		roles, err := svc.ListUserRoles(c.Request.Context(), c.Param("sub"))
		if err != nil {
			_ = c.Error(service.ToStatus(err))
			return
		}
		dtos := make([]gin.H, 0, len(roles))
		for _, ur := range roles {
			d := gin.H{"role_code": ur.RoleCode}
			if ur.ExpiresAt != nil {
				d["expires_at"] = ur.ExpiresAt.Format(time.RFC3339)
			}
			dtos = append(dtos, d)
		}
		c.JSON(http.StatusOK, gin.H{"roles": dtos})
	}
}

type grantUserRoleRequest struct {
	RoleCode  string     `json:"role_code" binding:"required"`
	ExpiresAt *time.Time `json:"expires_at"`
}

func grantUserRoleHandler(svc *service.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req grantUserRoleRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		err := svc.GrantUserRole(c.Request.Context(), c.Param("sub"), req.RoleCode, req.ExpiresAt)
		if err != nil {
			_ = c.Error(service.ToStatus(err))
			return
		}
		c.Status(http.StatusOK)
	}
}

func revokeUserRoleHandler(svc *service.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		err := svc.RevokeUserRole(c.Request.Context(), c.Param("sub"), c.Param("code"))
		if err != nil {
			_ = c.Error(service.ToStatus(err))
			return
		}
		c.Status(http.StatusOK)
	}
}

type grantUserPermissionRequest struct {
	PermissionKey string `json:"permission_key" binding:"required"`
}

func grantUserPermissionHandler(svc *service.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req grantUserPermissionRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		err := svc.GrantUserPermission(c.Request.Context(), c.Param("sub"), req.PermissionKey)
		if err != nil {
			_ = c.Error(service.ToStatus(err))
			return
		}
		c.Status(http.StatusOK)
	}
}

func revokeAllUserRolesHandler(svc *service.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		if err := svc.RevokeAllUserRoles(c.Request.Context(), c.Param("sub")); err != nil {
			_ = c.Error(service.ToStatus(err))
			return
		}
		c.Status(http.StatusOK)
	}
}

func departmentDTO(d *repo.Department) gin.H {
	dto := gin.H{"id": strconv.FormatInt(d.ID, 10), "name": d.Name, "dept_path": d.DeptPath}
	if d.ParentID != nil {
		dto["parent_id"] = strconv.FormatInt(*d.ParentID, 10)
	}
	return dto
}

func listDepartmentsHandler(svc *service.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		depts, err := svc.ListDepartments(c.Request.Context())
		if err != nil {
			_ = c.Error(service.ToStatus(err))
			return
		}
		dtos := make([]gin.H, 0, len(depts))
		for _, d := range depts {
			dtos = append(dtos, departmentDTO(d))
		}
		c.JSON(http.StatusOK, gin.H{"departments": dtos})
	}
}

type createDepartmentRequest struct {
	Name     string  `json:"name" binding:"required"`
	ParentID *string `json:"parent_id"`
}

func createDepartmentHandler(svc *service.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req createDepartmentRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		var parentID *int64
		if req.ParentID != nil {
			id, err := strconv.ParseInt(*req.ParentID, 10, 64)
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "parent_id 不合法"})
				return
			}
			parentID = &id
		}
		dept, err := svc.CreateDepartment(c.Request.Context(), req.Name, parentID)
		if err != nil {
			_ = c.Error(service.ToStatus(err))
			return
		}
		c.JSON(http.StatusOK, departmentDTO(dept))
	}
}

type assignUserDepartmentRequest struct {
	DepartmentID string `json:"department_id" binding:"required"`
}

func assignUserDepartmentHandler(svc *service.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req assignUserDepartmentRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		id, err := strconv.ParseInt(req.DepartmentID, 10, 64)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "department_id 不合法"})
			return
		}
		if err := svc.AssignUserDepartment(c.Request.Context(), c.Param("sub"), id); err != nil {
			_ = c.Error(service.ToStatus(err))
			return
		}
		c.Status(http.StatusOK)
	}
}
