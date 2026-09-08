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

// RegisterRoutes 挂载全部路由。⚠️ 全部标 besdk.Public 是阶段四的刻意
// 状态（同 erp-finance 等五个组件在阶段二的先例）：
//   - /authz/bundle 永久保持 Public——它本身就是其他组件判权限的数据
//     来源，不能靠它自己判权限（鸡生蛋），且不进 edge_routes、不经网关
//     暴露（assembly.yaml 注释、设计计划 §3）。
//   - /api/admin/** 的真实权限键已经在 assembly.yaml 声明好了
//     （infra.authz.admin），阶段五 Task 5 把 be-sdk 的判定换成真实
//     bundle 查找后，这里换成真实键——本组件自己也吃自己下发的 bundle
//     （README「自我鉴权」一节），到那之前先保持与其余组件一致的
//     Public 占位，不提前造一个只有它自己在用的判定分支。
//   - /api/me/permissions 语义上是"仅需登录，不需要具体权限键"——
//     be-sdk 目前只有 Public/具体权限键两档，还没有"已登录但不需要
//     权限键"这一档（README「已知缺口」）。这是 Task 5 该补的一个真实
//     缺口，本次实现中发现，不是当场解决。
func RegisterRoutes(eng *gin.Engine, svc *service.Service) {
	besdk.GET(eng, "/authz/bundle", besdk.Public, getBundleHandler(svc))

	besdk.GET(eng, "/api/me/permissions", besdk.Public, myPermissionsHandler(svc))

	g := eng.Group("/api/admin")
	besdk.GET(g, "/roles", besdk.Public, listRolesHandler(svc))
	besdk.POST(g, "/roles", besdk.Public, createRoleHandler(svc))
	besdk.GET(g, "/roles/:code", besdk.Public, getRoleHandler(svc))
	besdk.DELETE(g, "/roles/:code", besdk.Public, deleteRoleHandler(svc))
	besdk.POST(g, "/roles/:code/permissions", besdk.Public, grantRolePermissionHandler(svc))
	besdk.DELETE(g, "/roles/:code/permissions/:key", besdk.Public, revokeRolePermissionHandler(svc))

	besdk.GET(g, "/users/:sub/roles", besdk.Public, listUserRolesHandler(svc))
	besdk.POST(g, "/users/:sub/roles", besdk.Public, grantUserRoleHandler(svc))
	besdk.DELETE(g, "/users/:sub/roles/:code", besdk.Public, revokeUserRoleHandler(svc))
	besdk.POST(g, "/users/:sub/permissions", besdk.Public, grantUserPermissionHandler(svc))
	besdk.POST(g, "/users/:sub/revoke", besdk.Public, revokeAllUserRolesHandler(svc))
	besdk.POST(g, "/users/:sub/department", besdk.Public, assignUserDepartmentHandler(svc))

	besdk.GET(g, "/departments", besdk.Public, listDepartmentsHandler(svc))
	besdk.POST(g, "/departments", besdk.Public, createDepartmentHandler(svc))
}

// subDebugHeader 是"当前调用者是谁"的临时占位——be-sdk 还没有真实的 JWT
// 验签与 sub 提取（那是 Task 5 的范围，见 RegisterRoutes 顶部注释）。
// ⚠️ 这不是安全机制，只是让 /api/me/permissions 现在就能被测试与联调；
// 上线前必须换成从已验签 JWT 的 claims 里取 sub。
const subDebugHeader = "X-Authz-Debug-Sub"

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

func myPermissionsHandler(svc *service.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		sub := c.GetHeader(subDebugHeader)
		if sub == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "未登录"})
			return
		}
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
