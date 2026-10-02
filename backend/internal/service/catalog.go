package service

import (
	"fmt"
	"strings"
)

// PermissionCatalogEntry 的字段布局必须与 repo.PermissionCatalogEntry
// 逐字段一致（顺序、类型、数量）——service.go 用一次直接类型转换把它
// 变成 repo 层的类型，两边分层但不重复定义业务含义。
type PermissionCatalogEntry struct {
	Key            string
	Title          string
	Type           string
	OwnerComponent string
	Deprecated     string
}

// catalogMinColumns 是一行至少要有的列：key、title、type、owner_component。
// 第 5 列 deprecated 可以没有（四列行）或为空。
const catalogMinColumns = 4

// ParsePermissionCatalog 解析 PERMISSION_CATALOG 的值：项目权限键登记表
// （registry/permissions.tsv）的文件内容，部署时写成
// file://registry/permissions.tsv。格式：
//
//	key<TAB>title<TAB>type<TAB>owner_component<TAB>deprecated
//
// 按行切；空行、# 开头的行和表头行（第一列是 key）跳过；每行至少 4 列，
// 第 5 列 deprecated 可空。直接读登记表本身，而不是让别的工具生成一份
// 副本：副本要"记得重新生成"，漏一次新键就永远进不了 permissions 表。
//
// deprecated 非空的行照样返回：已经授给角色的旧键必须仍能在 permissions
// 表里解析到，废弃不是删除。
//
// 空字符串返回空切片、nil error（一个键都没有，不是格式错误）。
func ParsePermissionCatalog(raw string) ([]PermissionCatalogEntry, error) {
	var entries []PermissionCatalogEntry
	for i, line := range strings.Split(raw, "\n") {
		line = strings.TrimSuffix(line, "\r")
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
			continue
		}
		cols := strings.Split(line, "\t")
		if strings.TrimSpace(cols[0]) == "key" {
			continue // 表头
		}
		lineNo := i + 1
		if len(cols) < catalogMinColumns {
			return nil, fmt.Errorf("PERMISSION_CATALOG 第 %d 行只有 %d 列（至少要 key、title、type、owner_component 四列，制表符分隔）：%q",
				lineNo, len(cols), line)
		}
		key := strings.TrimSpace(cols[0])
		if key == "" {
			return nil, fmt.Errorf("PERMISSION_CATALOG 第 %d 行的 key 为空：%q", lineNo, line)
		}
		e := PermissionCatalogEntry{
			Key:            key,
			Title:          strings.TrimSpace(cols[1]),
			Type:           strings.TrimSpace(cols[2]),
			OwnerComponent: strings.TrimSpace(cols[3]),
		}
		if len(cols) > catalogMinColumns {
			e.Deprecated = strings.TrimSpace(cols[4])
		}
		entries = append(entries, e)
	}
	return entries, nil
}
