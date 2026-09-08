// migrate 是全拆态迁移容器的入口（合并态由外壳读 Module.Migrations 执行，
// 平台不为 local: true 的组件生成迁移容器，§13.3 铁律五）。
//
// 它在 backend/cmd/ 下，属于「装配」不是「模块」，module-check 的排除范围
// 就是 backend/cmd/——这里允许读 os.Getenv（§12.5 的零 os.Getenv 只管
// backend/module/ 与 backend/internal/）。
package main

import (
	"fmt"
	"log"
	"os"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
)

func main() {
	schema := os.Getenv("PG_SCHEMA")
	if schema == "" {
		schema = "infra_authz"
	}
	// ⚠️ x-migrations-table 只给裸表名，schema 完全交给 search_path 一个
	// 参数负责（同 mdm-product/erp-inventory/erp-finance 踩过的坑）。
	dsn := fmt.Sprintf(
		"postgres://%s:%s@%s:%s/%s?sslmode=disable"+
			"&search_path=%s"+
			"&x-migrations-table=schema_migrations_infra_authz",
		os.Getenv("DATABASE_USER"), os.Getenv("DATABASE_PASSWORD"),
		os.Getenv("DATABASE_HOST"), os.Getenv("DATABASE_PORT"),
		os.Getenv("DATABASE_NAME"), schema,
	)

	m, err := migrate.New("file://migrations", dsn)
	if err != nil {
		log.Fatalf("迁移初始化失败：%v", err)
	}
	if len(os.Args) > 1 && os.Args[1] == "down" {
		if err := m.Down(); err != nil && err != migrate.ErrNoChange {
			log.Fatalf("迁移回滚失败：%v", err)
		}
		return
	}
	// ⚠️ ErrNoChange 不是错误。迁移必须能连跑两次都成功（§13.3 铁律五）。
	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		log.Fatalf("迁移失败：%v", err)
	}
	log.Println("迁移完成")
}
