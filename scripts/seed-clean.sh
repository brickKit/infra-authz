#!/usr/bin/env bash
# 撤销 seed.sh 灌的角色/部门/授权——不碰 registry/permissions.tsv 灌进
# permissions 表的那 42 条真实权限键（那是 C14 修的正向路径，不是种子
# 数据）。
set -euo pipefail
C_GRN=$'\033[32m'; C_OFF=$'\033[0m'
ok()  { echo "${C_GRN}✓${C_OFF} $*"; }

docker exec -i be-postgres psql -U postgres -d brickkit_db -v ON_ERROR_STOP=1 -q <<'SQL'
SET search_path TO infra_authz;
-- role_permissions/user_roles 都对 roles.code 建了 ON DELETE CASCADE，
-- 删角色这一行就够了。
DELETE FROM roles WHERE code IN ('dev_superuser', 'dev_sales_rep', 'dev_warehouse_manager', 'dev_finance_viewer');

-- departments/user_departments 之间没有 ON DELETE CASCADE（阶段三的
-- 极简部门表，见 repo/departments.go 顶部注释），user_departments 先删、
-- 子部门再删、最后删父部门——顺序反了会撞外键。
DELETE FROM user_departments WHERE department_id IN (
  SELECT id FROM departments WHERE name IN ('「本地测试」华东分部', '「本地测试」华南分部', '「本地测试」总公司')
);
DELETE FROM departments WHERE name IN ('「本地测试」华东分部', '「本地测试」华南分部');
DELETE FROM departments WHERE name = '「本地测试」总公司';
SQL
ok "已撤销全部测试角色 + 部门树（不存在也不报错）"
