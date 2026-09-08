// Package module 是 infra-authz 唯一的装配入口（全局约束 §K、设计书
// §12.5.1、§13.3 铁律七）。单跑与合并走同一个 New 函数；模块只交回零件
// （handler、gRPC 注册函数、迁移、后台循环），谁去 Listen、谁开池、
// 谁 init OTel、谁装信号处理器，全归调用方。
package module

import (
	"context"
	"time"

	besdk "github.com/brickKit/be-sdk-go"
	authzv1 "github.com/brickKit/infra-authz/gen/infra/authz/v1"
	"google.golang.org/grpc"

	grpcapi "github.com/brickKit/infra-authz/backend/internal/grpc"
	httpapi "github.com/brickKit/infra-authz/backend/internal/http"
	"github.com/brickKit/infra-authz/backend/internal/partition"
	"github.com/brickKit/infra-authz/backend/internal/repo"
	"github.com/brickKit/infra-authz/backend/internal/service"
	"github.com/brickKit/infra-authz/migrations"
)

// New 构造 infra-authz 模块。签名一个字都不许改（§12.5.1）——62 个
// 组件都是这一个签名，外壳启动器与 be-ops 产出 4 都按它生成。
func New(ctx context.Context, rt *besdk.Runtime) (*besdk.Module, error) {
	// ⚠️ 配置只从 rt.Config 来，模块里零 os.Getenv（§12.5.3、决策 110）。
	schema := rt.Config.StringOr("pgSchema", "infra_authz")
	role := schema + "_rw"
	accessTokenTTL := time.Duration(rt.Config.IntOr("accessTokenTtlSeconds", 600)) * time.Second
	defaultOrgID := rt.Config.StringOr("defaultOrgId", "1")
	permissionCatalog := rt.Config.StringOr("permissionCatalog", "")
	bootstrapAdminSub := rt.Config.StringOr("bootstrapAdminSub", "")

	// ⚠️ 池从 rt.DB 来，不许自己 sql.Open（§13.3 铁律二）。
	r := repo.New(rt.DB, role, schema)
	svc := service.New(r, accessTokenTTL, defaultOrgID)

	// HTTP：engine 必须用 besdk.NewGinEngine，它已挂好 OTel / request-id /
	// error→status / PII 脱敏日志 / RED 指标 / /healthz / /metrics。
	eng := besdk.NewGinEngine(rt)
	httpapi.RegisterRoutes(eng, svc)

	return &besdk.Module{
		HTTPHandler: eng,

		// ⚠️ gRPC 一个不省，而且由调用方在 extraPorts["grpc"] 上 Listen
		// （§1.5 原则一）。
		RegisterGRPC: func(gs *grpc.Server) {
			authzv1.RegisterAuthzServiceServer(gs, grpcapi.New(svc))
		},

		Migrations: migrations.FS, // 合并态由外壳按拓扑顺序跑（§13.3 铁律五）

		// Start 先做两件一次性的事（目录同步 + 自举管理员），再起两个
		// 并发的后台循环（Outbox 推送 + 分区维护）。一次性的事失败只
		// 记日志继续——permissionCatalog 为空/bootstrapAdminSub 为空
		// 都是合法状态（见各自函数注释），真正的数据库故障会在后续
		// 请求处理时暴露，不需要在这里让整个组件启动失败。
		Start: func(ctx context.Context) error {
			if err := svc.SyncPermissionCatalog(ctx, permissionCatalog); err != nil {
				rt.Logger.Error("同步权限目录失败", "error", err)
			}
			if err := svc.EnsureBootstrapAdmin(ctx, bootstrapAdminSub); err != nil {
				rt.Logger.Error("自举管理员失败", "error", err)
			}

			errCh := make(chan error, 2)
			go func() { errCh <- besdk.StartOutboxPump(ctx, rt.DB, schema, rt.NATS, rt.Logger) }()
			go func() { errCh <- partition.Start(ctx, rt.DB, role, schema, rt.Logger) }()

			select {
			case <-ctx.Done():
				return nil
			case err := <-errCh:
				return err // ⚠️ 返回 error，不许 log.Fatal：一个模块退进程 = 整组组件一起没了
			}
		},
		Stop: func(ctx context.Context) error { return nil }, // 后台循环靠 ctx 退出
	}, nil
}
