package service

import (
	"strings"
	"testing"
)

// registryFragment 是项目 registry/permissions.tsv 的真实形态：表头行、制表符
// 分隔、中文标题、第 5 列 deprecated 大多为空、文件末尾没有换行。
const registryFragment = "key\ttitle\ttype\towner_component\tdeprecated\n" +
	"crm.opportunity.edit\t编辑商机\taction\tcrm/opportunity\t\n" +
	"erp.finance.close\t关账/反关账/锁定期间\taction\terp/finance\t\n" +
	"erp.sales.legacy_export\t导出销售订单（旧）\taction\terp/sales\t2026-09-01 改用 erp.sales.export\n" +
	"mdm.product.view\t查看产品主数据\tpage\tmdm/product\t"

func TestParsePermissionCatalog_空字符串返回空切片不报错(t *testing.T) {
	entries, err := ParsePermissionCatalog("")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("空字符串应该返回空切片，得到 %+v", entries)
	}
}

func TestParsePermissionCatalog_注册表TSV按行解析并跳过表头(t *testing.T) {
	entries, err := ParsePermissionCatalog(registryFragment)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 4 {
		t.Fatalf("期望 4 条（表头不算），得到 %d：%+v", len(entries), entries)
	}
	want := PermissionCatalogEntry{Key: "erp.finance.close", Title: "关账/反关账/锁定期间", Type: "action", OwnerComponent: "erp/finance"}
	if entries[1] != want {
		t.Fatalf("中文标题、组件 ID 应原样保留：期望 %+v，得到 %+v", want, entries[1])
	}
	if entries[3].Key != "mdm.product.view" || entries[3].OwnerComponent != "mdm/product" {
		t.Fatalf("末尾没有换行的最后一行也要解析：%+v", entries[3])
	}
}

func TestParsePermissionCatalog_废弃的键照样同步并带上废弃说明(t *testing.T) {
	entries, err := ParsePermissionCatalog(registryFragment)
	if err != nil {
		t.Fatal(err)
	}
	var found *PermissionCatalogEntry
	for i := range entries {
		if entries[i].Key == "erp.sales.legacy_export" {
			found = &entries[i]
		}
	}
	if found == nil {
		t.Fatalf("deprecated 非空的键也要出现在目录里（已授出的旧键要仍能在 permissions 表里解析到）：%+v", entries)
	}
	if found.Deprecated != "2026-09-01 改用 erp.sales.export" {
		t.Fatalf("deprecated 列应原样带出，得到 %q", found.Deprecated)
	}
	for _, e := range entries {
		if e.Key != "erp.sales.legacy_export" && e.Deprecated != "" {
			t.Fatalf("deprecated 为空的行不该带出废弃说明：%+v", e)
		}
	}
}

func TestParsePermissionCatalog_跳过空行与注释行(t *testing.T) {
	raw := "# 权限键登记表\n\nkey\ttitle\ttype\towner_component\tdeprecated\n\n" +
		"erp.sales.view\t查看销售订单\tpage\terp/sales\t\n# 中间的注释\n\n" +
		"mdm.customer.view\t查看客户主数据\tpage\tmdm/customer\t\n"
	entries, err := ParsePermissionCatalog(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || entries[0].Key != "erp.sales.view" || entries[1].Key != "mdm.customer.view" {
		t.Fatalf("空行、# 开头的行、表头都应跳过：%+v", entries)
	}
}

func TestParsePermissionCatalog_没有deprecated列的四列行也接受(t *testing.T) {
	entries, err := ParsePermissionCatalog("erp.sales.view\t查看销售订单\tpage\terp/sales")
	if err != nil {
		t.Fatal(err)
	}
	want := PermissionCatalogEntry{Key: "erp.sales.view", Title: "查看销售订单", Type: "page", OwnerComponent: "erp/sales"}
	if len(entries) != 1 || entries[0] != want {
		t.Fatalf("期望 %+v，得到 %+v", want, entries)
	}
}

func TestParsePermissionCatalog_Windows换行也能解析(t *testing.T) {
	entries, err := ParsePermissionCatalog("key\ttitle\ttype\towner_component\tdeprecated\r\nerp.sales.view\t查看销售订单\tpage\terp/sales\t\r\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].OwnerComponent != "erp/sales" || entries[0].Deprecated != "" {
		t.Fatalf("行尾的 \\r 不该留在最后一列里：%+v", entries)
	}
}

func TestParsePermissionCatalog_列数不足报错并给出行号(t *testing.T) {
	raw := "key\ttitle\ttype\towner_component\tdeprecated\n" +
		"erp.sales.view\t查看销售订单\tpage\terp/sales\t\n" +
		"erp.sales.create\t新建销售订单\taction\n"
	_, err := ParsePermissionCatalog(raw)
	if err == nil {
		t.Fatal("少于 4 列应该报错")
	}
	if !strings.Contains(err.Error(), "第 3 行") {
		t.Fatalf("错误信息要给出行号（第 3 行），得到：%v", err)
	}
}

func TestParsePermissionCatalog_key为空报错并给出行号(t *testing.T) {
	raw := "erp.sales.view\t查看销售订单\tpage\terp/sales\t\n\t查看客户\tpage\tmdm/customer\t\n"
	_, err := ParsePermissionCatalog(raw)
	if err == nil {
		t.Fatal("key 为空应该报错")
	}
	if !strings.Contains(err.Error(), "第 2 行") {
		t.Fatalf("错误信息要给出行号（第 2 行），得到：%v", err)
	}
}

func TestParsePermissionCatalog_逗号竖线格式不再接受(t *testing.T) {
	_, err := ParsePermissionCatalog("erp.sales.view|查看销售订单|page|erp/sales,mdm.customer.view|查看客户主数据|page|mdm/customer")
	if err == nil {
		t.Fatal("PERMISSION_CATALOG 的值是注册表 TSV，逗号竖线串应该报错，而不是被当成一个奇怪的键")
	}
}

// TestParsePermissionCatalog_repo类型转换字段布局一致 是一条编译期断言：
// service.PermissionCatalogEntry 与 repo.PermissionCatalogEntry 的字段
// 布局必须逐字段一致，否则 service.go 里那次直接类型转换编译不过。
func TestParsePermissionCatalog_repo类型转换字段布局一致(t *testing.T) {
	e := PermissionCatalogEntry{Key: "k", Title: "t", Type: "ty", OwnerComponent: "o", Deprecated: "d"}
	_ = e // 真正的断言在 service.go 的 repo.PermissionCatalogEntry(e) 那一行，能编译就是过
}
