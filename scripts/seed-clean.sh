#!/usr/bin/env bash
# 撤销 seed.sh 灌的角色/权限授权——不碰 registry/permissions.tsv 灌进
# permissions 表的那 42 条真实权限键（那是 C14 修的正向路径，不是种子
# 数据），只删本脚本自己建的角色相关三行。
set -euo pipefail
C_GRN=$'\033[32m'; C_OFF=$'\033[0m'
ok()  { echo "${C_GRN}✓${C_OFF} $*"; }

SEED_ROLE="dev_superuser"

docker exec -i be-postgres psql -U postgres -d brickkit_db -v ON_ERROR_STOP=1 -q <<SQL
SET search_path TO infra_authz;
-- role_permissions/user_roles 都对 roles.code 建了 ON DELETE CASCADE，
-- 删这一行就够了。
DELETE FROM roles WHERE code = '$SEED_ROLE';
SQL
ok "已撤销角色 $SEED_ROLE 及其全部授权（不存在也不报错）"
