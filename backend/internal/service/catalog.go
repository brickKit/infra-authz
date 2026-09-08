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
}

// ParsePermissionCatalog 解析 config.permissionCatalog 的编码格式
// （阶段三 Task 4 设计决策，见 README「permissionCatalog 编码格式」）：
//
//	条目之间用逗号分隔，条目内部 4 个字段用竖线分隔：
//	key|title|type|owner_component,key2|title2|type2|owner_component2
//
// 选 `|` 做字段分隔符、`,` 做条目分隔符，是因为两者都不可能出现在
// 权限键（`{domain}.{aggregate}.{action}` 格式，§3.7）或组件 ID
// （`{domain}/{name}`）里，而中文标题几乎不会含有这两个符号——比
// 传 JSON 更省字节，也不会撞上"平台把 YAML 数组渲染成 [a b c]"那条雷
// （§14.1.2 明确要求逗号分隔字符串，不能是数组）。
//
// 空字符串返回空切片、nil error——组件刚启动、还没有任何组件声明权限
// 键是合法状态，不是错误。
func ParsePermissionCatalog(raw string) ([]PermissionCatalogEntry, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	rawEntries := strings.Split(raw, ",")
	entries := make([]PermissionCatalogEntry, 0, len(rawEntries))
	for i, re := range rawEntries {
		fields := strings.Split(re, "|")
		if len(fields) != 4 {
			return nil, fmt.Errorf("permissionCatalog 第 %d 条格式不对（要 key|title|type|owner_component）：%q", i+1, re)
		}
		key := strings.TrimSpace(fields[0])
		if key == "" {
			return nil, fmt.Errorf("permissionCatalog 第 %d 条的 key 不能为空：%q", i+1, re)
		}
		entries = append(entries, PermissionCatalogEntry{
			Key: key, Title: fields[1], Type: fields[2], OwnerComponent: fields[3],
		})
	}
	return entries, nil
}
