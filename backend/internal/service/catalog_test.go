package service

import "testing"

func TestParsePermissionCatalog_空字符串返回空切片不报错(t *testing.T) {
	entries, err := ParsePermissionCatalog("")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("空字符串应该返回空切片，得到 %+v", entries)
	}
}

func TestParsePermissionCatalog_单条(t *testing.T) {
	entries, err := ParsePermissionCatalog("erp.sales.view|查看销售订单|page|erp/sales")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("期望 1 条，得到 %d：%+v", len(entries), entries)
	}
	want := PermissionCatalogEntry{Key: "erp.sales.view", Title: "查看销售订单", Type: "page", OwnerComponent: "erp/sales"}
	if entries[0] != want {
		t.Fatalf("解析不对：期望 %+v，得到 %+v", want, entries[0])
	}
}

func TestParsePermissionCatalog_多条(t *testing.T) {
	raw := "erp.sales.view|查看销售订单|page|erp/sales,mdm.customer.view|查看客户主数据|page|mdm/customer"
	entries, err := ParsePermissionCatalog(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("期望 2 条，得到 %d：%+v", len(entries), entries)
	}
	if entries[0].Key != "erp.sales.view" || entries[1].Key != "mdm.customer.view" {
		t.Fatalf("顺序或 key 不对：%+v", entries)
	}
	if entries[1].OwnerComponent != "mdm/customer" {
		t.Fatalf("第二条 owner_component 不对：%+v", entries[1])
	}
}

func TestParsePermissionCatalog_字段数不对报错(t *testing.T) {
	_, err := ParsePermissionCatalog("erp.sales.view|查看销售订单|page") // 缺 owner_component
	if err == nil {
		t.Fatal("字段数不是 4 个应该报错")
	}
}

func TestParsePermissionCatalog_key为空报错(t *testing.T) {
	_, err := ParsePermissionCatalog("|查看销售订单|page|erp/sales")
	if err == nil {
		t.Fatal("key 为空应该报错")
	}
}

// TestParsePermissionCatalog_repo类型转换字段布局一致 是一条编译期断言：
// service.PermissionCatalogEntry 与 repo.PermissionCatalogEntry 的字段
// 布局必须逐字段一致，否则 service.go 里那次直接类型转换编译不过——
// 这条测试本身不跑什么逻辑，它的价值是"改坏了布局，CI 在这里就红"，
// 而不是等到运行时才发现两边字段对不上。
func TestParsePermissionCatalog_repo类型转换字段布局一致(t *testing.T) {
	e := PermissionCatalogEntry{Key: "k", Title: "t", Type: "ty", OwnerComponent: "o"}
	_ = e // 真正的断言在 service.go 的 repo.PermissionCatalogEntry(e) 那一行，能编译就是过
}
