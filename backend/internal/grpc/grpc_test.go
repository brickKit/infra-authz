package grpc

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"testing"
	"time"

	authzv1 "github.com/brickKit/infra-authz/gen/infra/authz/v1"
	_ "github.com/jackc/pgx/v5/stdlib"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/brickKit/infra-authz/v2/backend/internal/repo"
	"github.com/brickKit/infra-authz/v2/backend/internal/service"
)

func serverOn(db *sql.DB) authzv1.AuthzServiceServer {
	return New(service.New(repo.New(db, "infra_authz_rw", "infra_authz"), 10*time.Minute, "1"))
}

// 数据库出错不是"查不到"：调用方拿到空列表会以为这些角色都不存在。
func TestBatchGetRoles_数据库出错返回错误而不是空列表(t *testing.T) {
	db, err := sql.Open("pgx", "postgres://nobody@127.0.0.1:1/nothing")
	if err != nil {
		t.Fatal(err)
	}
	db.Close() // 之后的每次查询都失败：sql: database is closed

	resp, err := serverOn(db).BatchGetRoles(context.Background(), &authzv1.BatchGetRolesRequest{Codes: []string{"authz_admin"}})
	if err == nil {
		t.Fatalf("数据库不可用时应返回错误，实际返回 %d 个角色、没有错误", len(resp.GetRoles()))
	}
	if status.Code(err) != codes.Internal {
		t.Fatalf("应映射成 Internal，实际 %v", err)
	}
}

func TestBatchGetRoles_查不到的code省略不报错(t *testing.T) {
	dsn := os.Getenv("TEST_PG_DSN")
	if dsn == "" {
		t.Skip("未设置 TEST_PG_DSN")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	missing := fmt.Sprintf("missing_%d", time.Now().UnixNano())
	// authz_admin 由迁移种下，一定存在。
	resp, err := serverOn(db).BatchGetRoles(context.Background(), &authzv1.BatchGetRolesRequest{Codes: []string{"authz_admin", missing}})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Roles) != 1 || resp.Roles[0].Code != "authz_admin" {
		t.Fatalf("应只返回存在的 authz_admin，得到 %+v", resp.Roles)
	}
}
