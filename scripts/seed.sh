#!/usr/bin/env bash
# 灌本地开发用的种子授权：给万能测试用户（infra-iam-casdoor 的
# scripts/seed.sh 建的那个）建一个持有全部权限键的角色（同 mdm-customer/
# mdm-product 的既有判据，总纲 SOP-W-7：种子数据归各组件自己持有）。
#
# ⚠️ 直接写库，不经本组件的 REST admin API——这是刻意的，不是偷懒：
# 这个开发环境没配 bootstrapAdminSub，没有任何账号能走合法的 REST admin
# API 去做首次授权（见 infra/seed-data/README.md 的既有说明），先有一个
# "已经有权限的账号"才能用它去调 admin API 授权别人，第一个账号只能
# 绕开 API 直接写库。
#
# 用法：make -C components/infra/authz seed——要求 Casdoor 已经在跑，且
# infra-iam-casdoor 的种子用户已存在（本脚本会自己去 Casdoor 查，没有
# 就报错提示先跑那边的 make seed，不是静默失败）。
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ROOT="$(cd "$DIR/../../.." && pwd)"

C_GRN=$'\033[32m'; C_RED=$'\033[31m'; C_OFF=$'\033[0m'
ok()  { echo "${C_GRN}✓${C_OFF} $*"; }
die() { echo "${C_RED}✗${C_OFF} $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "缺少命令：$1"; }
need curl; need python3; need docker

CASDOOR_URL="${CASDOOR_URL:-http://localhost:8000}"
SEED_USER="dev.superuser"
SEED_ROLE="dev_superuser"

curl -sf -o /dev/null "$CASDOOR_URL/api/health" || die "Casdoor（$CASDOOR_URL）连不上，先 brickkit up"

# 独立向 Casdoor 查 sub，不依赖 infra-iam-casdoor 的 seed.sh 用任何方式
# 传参给这里——两边各自都能单独跑通（同 mdm-customer/mdm-product 的
# "组件自己的 make seed 单独跑就能拿到完整数据"判据），只是共享同一个
# 约定好的用户名。
COOKIE_JAR="$(mktemp)"
trap 'rm -f "$COOKIE_JAR"' EXIT
curl -c "$COOKIE_JAR" -s -o /dev/null -X POST "$CASDOOR_URL/api/login" \
  -H "Content-Type: application/json" \
  -d '{"application":"app-built-in","organization":"built-in","username":"admin","password":"123","autoSignin":true,"type":"login"}'
USER_JSON="$(curl -b "$COOKIE_JAR" -s "$CASDOOR_URL/api/get-user?id=brickkit/$SEED_USER")"
SEED_SUB="$(echo "$USER_JSON" | python3 -c 'import json,sys; d=json.load(sys.stdin)["data"]; print(d["id"] if d else "")')"
[ -n "$SEED_SUB" ] || die "Casdoor 里找不到 $SEED_USER——先 make -C components/infra/iam-casdoor seed"

psqlx() { docker exec -i be-postgres psql -U postgres -d brickkit_db -v ON_ERROR_STOP=1 "$@"; }

# 权限键按 registry/permissions.tsv 现读现灌，不依赖 permissions 表里
# 可能混着的其它测试残留数据。
PERM_KEYS="$(python3 -c "
import csv
with open('$ROOT/registry/permissions.tsv') as f:
    rows = [r for r in csv.DictReader(f, delimiter='\t') if not r['deprecated'].strip()]
for r in rows:
    print(r['key'])
")"

{
  echo "SET search_path TO infra_authz;"
  echo "INSERT INTO roles (code, name, is_system) VALUES ('$SEED_ROLE', '「本地测试」超级测试角色', false) ON CONFLICT (code) DO NOTHING;"
  while IFS= read -r key; do
    [ -n "$key" ] || continue
    echo "INSERT INTO role_permissions (role_code, permission_key) VALUES ('$SEED_ROLE', '$key') ON CONFLICT DO NOTHING;"
  done <<< "$PERM_KEYS"
  echo "INSERT INTO user_roles (sub, role_code) VALUES ('$SEED_SUB', '$SEED_ROLE') ON CONFLICT DO NOTHING;"
} | psqlx -q

ok "已授予 $SEED_USER（sub=$SEED_SUB）角色 $SEED_ROLE（$(echo "$PERM_KEYS" | grep -c .) 个权限键）"
echo "   ⚠️ bundle 是各组件每 ~15s 轮询一次拉进内存的——刚写完立刻拿这个身份去调别的组件，有真实的竞态窗口，看到 403 先等 18 秒再试"
