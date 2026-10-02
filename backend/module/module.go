// Package module 是 infra-authz 唯一的装配入口。单跑与进外壳走同一个 New
// 函数；模块只交回零件（handler、gRPC 注册函数、后台循环），谁去 Listen、
// 谁开池、谁 init OTel、谁装信号处理器，全归调用方——进了外壳，进程级的
// 东西只能有一份。
package module

import (
	"context"
	"time"

	besdk "github.com/brickKit/be-sdk-go"
	authzv1 "github.com/brickKit/infra-authz/gen/infra/authz/v1"
	"google.golang.org/grpc"

	grpcapi "github.com/brickKit/infra-authz/v2/backend/internal/grpc"
	httpapi "github.com/brickKit/infra-authz/v2/backend/internal/http"
	"github.com/brickKit/infra-authz/v2/backend/internal/partition"
	"github.com/brickKit/infra-authz/v2/backend/internal/repo"
	"github.com/brickKit/infra-authz/v2/backend/internal/service"
)

// New 构造 infra-authz 模块。签名不许改：外壳的 Registry 按这个签名登记成员。
func New(ctx context.Context, rt *besdk.Runtime) (*besdk.Module, error) {
	// ⚠️ 配置只从 rt.Config 来，模块里零 os.Getenv：进了外壳，进程环境是外壳的，
	// 成员各自的配置只在 rt.Config 里。
	schema := rt.Config.StringOr("PG_SCHEMA", "infra_authz")
	role := schema + "_rw"
	accessTokenTTL := time.Duration(rt.Config.IntOr("ACCESS_TOKEN_TTL_SECONDS", 600)) * time.Second
	defaultOrgID := rt.Config.StringOr("DEFAULT_ORG_ID", "1")
	permissionCatalog := rt.Config.StringOr("PERMISSION_CATALOG", "")
	bootstrapAdminSub := rt.Config.StringOr("BOOTSTRAP_ADMIN_SUB", "")

	// ⚠️ 池从 rt.DB 来，不许自己 sql.Open：外壳里所有成员共用一个池。
	r := repo.New(rt.DB, role, schema)
	svc := service.New(r, accessTokenTTL, defaultOrgID)

	// HTTP：engine 必须用 besdk.NewGinEngine，它已挂好 OTel / request-id /
	// error→status / PII 脱敏日志 / RED 指标 / /healthz / /metrics。
	eng := besdk.NewGinEngine(rt)
	httpapi.RegisterRoutes(eng, svc)

	return &besdk.Module{
		HTTPHandler: eng,

		// ⚠️ component.yaml 声明了 grpc 额外端口，就必须返回 RegisterGRPC
		// （否则 SDK 拒绝启动）；由调用方在这个端口上 Listen。
		RegisterGRPC: func(gs *grpc.Server) {
			authzv1.RegisterAuthzServiceServer(gs, grpcapi.New(svc))
		},

		// Start 先做两件一次性的事（权限目录同步 + 自举管理员），再起两个
		// 并发的后台循环（Outbox 推送 + 分区维护）。一次性的事失败只记
		// ERROR 日志继续：目录格式错了、库暂时不可达，bundle 照样能用表里
		// 已有的内容下发，下一次重启再同步；为这个让整个组件起不来，所有
		// 组件的受保护路由都会跟着 503。目录里一个键都没有、
		// BOOTSTRAP_ADMIN_SUB 为空，都是合法状态（见各自函数注释）。
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
