#!/usr/bin/env bash
# 灌本地开发用的种子授权：
# ① 给万能测试用户（infra-iam-casdoor 的 scripts/seed.sh 建的那个）建一个
#    持有全部权限键的角色（同 mdm-customer/mdm-product 的既有判据，总纲
#    SOP-W-7：种子数据归各组件自己持有）——这一步直接写库，是刻意的，
#    不是偷懒：这个开发环境没配 bootstrapAdminSub，没有任何账号能走合法
#    的 REST admin API 去做首次授权，先有一个"已经有权限的账号"才能用
#    它去调 admin API 授权别人，第一个账号只能绕开 API 直接写库。
# ② 有了这个账号之后，②往后全部改走真实 REST admin API（不再直接写
#    库）：建 2 个部门（华东/华南）+ 3 个权限子集角色（销售/仓管/财务
#    只读），把 infra-iam-casdoor 建的另外 3 个测试用户分别归到对应
#    部门+角色——这是总纲 SOP-W-7"数据权限维度要有真实存在感"这条
#    判据的落地：种子数据不能只有一个全权限 admin 视角。
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
IAM_URL="${IAM_URL:-http://localhost:8200}"
AUTHZ_REST="${AUTHZ_REST:-http://localhost:8223}"
SEED_USER="dev.superuser"
SEED_ROLE="dev_superuser"
SEED_APP="local-dev-seed-app"
SEED_PASSWORD="DevSeed123!"

curl -sf -o /dev/null "$CASDOOR_URL/api/health" || die "Casdoor（$CASDOOR_URL）连不上，先 brickkit up"
curl -sf -o /dev/null "$AUTHZ_REST/healthz" || die "infra-authz（$AUTHZ_REST）连不上，先 brickkit up"

# 独立向 Casdoor 查 sub，不依赖 infra-iam-casdoor 的 seed.sh 用任何方式
# 传参给这里——两边各自都能单独跑通（同 mdm-customer/mdm-product 的
# "组件自己的 make seed 单独跑就能拿到完整数据"判据），只是共享同一个
# 约定好的用户名。
COOKIE_JAR="$(mktemp)"
trap 'rm -f "$COOKIE_JAR"' EXIT
curl -c "$COOKIE_JAR" -s -o /dev/null -X POST "$CASDOOR_URL/api/login" \
  -H "Content-Type: application/json" \
  -d '{"application":"app-built-in","organization":"built-in","username":"admin","password":"123","autoSignin":true,"type":"login"}'
sub_of() {
  curl -b "$COOKIE_JAR" -s "$CASDOOR_URL/api/get-user?id=brickkit/$1" | python3 -c 'import json,sys; d=json.load(sys.stdin)["data"]; print(d["id"] if d else "")'
}
SEED_SUB="$(sub_of "$SEED_USER")"
[ -n "$SEED_SUB" ] || die "Casdoor 里找不到 $SEED_USER——先 make -C components/infra/iam-casdoor seed"

psqlx() { docker exec -i be-postgres psql -U postgres -d brickkit_db -v ON_ERROR_STOP=1 "$@"; }

echo "── ① 直接写库：给 $SEED_USER 建全权限角色（唯一一处绕开 REST API 的首次授权）──"
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

echo "   等 18 秒，让本组件自己的权限 bundle 轮询到刚写的授权（本组件自吃自己下发的 bundle）……"
sleep 18

echo "── ② 换 $SEED_USER 的真实 JWT，后面全部走 REST admin API ──"
APP_JSON="$(curl -b "$COOKIE_JAR" -s "$CASDOOR_URL/api/get-application?id=admin/$SEED_APP")"
CLIENT_ID="$(echo "$APP_JSON" | python3 -c 'import json,sys; print(json.load(sys.stdin, strict=False)["data"]["clientId"])')"
CLIENT_SECRET="$(echo "$APP_JSON" | python3 -c 'import json,sys; print(json.load(sys.stdin, strict=False)["data"]["clientSecret"])')"
ID_TOKEN="$(curl -s -X POST "$CASDOOR_URL/api/login/oauth/access_token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "grant_type=password" \
  --data-urlencode "username=$SEED_USER" \
  --data-urlencode "password=$SEED_PASSWORD" \
  --data-urlencode "client_id=$CLIENT_ID" \
  --data-urlencode "client_secret=$CLIENT_SECRET" \
  --data-urlencode "scope=openid profile email" | python3 -c 'import json,sys; print(json.load(sys.stdin)["id_token"])')"
[ -n "$ID_TOKEN" ] || die "拿不到 Casdoor id_token"
ACCESS_TOKEN="$(curl -s -X POST "$IAM_URL/api/iam/token" \
  -H "Content-Type: application/json" \
  -d "{\"casdoor_id_token\": \"$ID_TOKEN\"}" | python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])')"
[ -n "$ACCESS_TOKEN" ] || die "换应用 JWT 失败"
ok "已换到真实应用 JWT"

authed() { curl -s -H "Authorization: Bearer $ACCESS_TOKEN" -H "Content-Type: application/json" "$@"; }

echo "── ③ 建部门树：总公司 → 华东分部/华南分部（幂等：已存在同名部门直接复用）──"
# ⚠️ 本组件没有"按名字查部门"的接口，只有 ListDepartments——幂等靠
# 本脚本自己在返回列表里按 name 找，不是靠服务端 upsert。
find_dept_id() {
  authed "$AUTHZ_REST/api/admin/departments" | python3 -c "
import json,sys
data = json.load(sys.stdin)
for d in data.get('departments', []):
    if d['name'] == '$1':
        print(d['id']); break
"
}
create_dept() {
  local name="$1" parent_id="${2:-}"
  local body
  if [ -n "$parent_id" ]; then
    body="{\"name\":\"$name\",\"parent_id\":\"$parent_id\"}"
  else
    body="{\"name\":\"$name\"}"
  fi
  authed -X POST "$AUTHZ_REST/api/admin/departments" -d "$body" \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])'
}
ensure_dept() {
  # ⚠️ 实测踩坑：这个函数的返回值靠"最后一行 echo"经命令替换（`$()`）
  # 传出去，函数体里絶对不能再调 ok()（它 echo 到 stdout）——两条 stdout
  # 混在一起，调用方拿到的会是"状态行+真正的 id"这坨多行垃圾，传给
  # 下一层当 parent_id 用会直接 400。状态提示一律用 >&2 写到 stderr，
  # 不进被捕获的那条 stdout。
  local name="$1" parent_id="${2:-}"
  local id
  id="$(find_dept_id "$name")"
  if [ -z "$id" ]; then
    id="$(create_dept "$name" "$parent_id")"
    ok "已建部门「$name」（id=$id）" >&2
  else
    ok "部门「$name」已存在（id=$id），跳过创建" >&2
  fi
  echo "$id"
}

ROOT_DEPT_ID="$(ensure_dept "「本地测试」总公司")"
EAST_DEPT_ID="$(ensure_dept "「本地测试」华东分部" "$ROOT_DEPT_ID")"
SOUTH_DEPT_ID="$(ensure_dept "「本地测试」华南分部" "$ROOT_DEPT_ID")"

echo "── ④ 建 3 个权限子集角色（覆盖不同岗位画像，不是只有全权限 admin）──"
# ensure_role <code> <name> <perm1,perm2,...>：幂等——POST /roles 对已
# 存在的 code 会报错（唯一约束），先 GET 判断存在与否；权限授予本身
# 走 ON CONFLICT 语义的 grant 接口，重复调用不报错。
ensure_role() {
  local code="$1" name="$2"
  local status
  status="$(authed -o /dev/null -w '%{http_code}' "$AUTHZ_REST/api/admin/roles/$code")"
  if [ "$status" = "404" ]; then
    authed -X POST "$AUTHZ_REST/api/admin/roles" -d "{\"code\":\"$code\",\"name\":\"$name\"}" >/dev/null
    ok "已建角色 $code（$name）"
  else
    ok "角色 $code 已存在，跳过创建"
  fi
}
grant_perm() {
  authed -X POST "$AUTHZ_REST/api/admin/roles/$1/permissions" -d "{\"permission_key\":\"$2\"}" >/dev/null
}

ensure_role dev_sales_rep "「本地测试」销售代表"
for k in mdm.customer.view mdm.customer.create mdm.customer.update mdm.customer.add_contact \
         mdm.product.view crm.opportunity.view crm.opportunity.edit crm.opportunity.win \
         erp.sales.view erp.sales.create erp.sales.confirm \
         infra.workflow.task.view infra.notification.view infra.notification.preference.edit; do
  grant_perm dev_sales_rep "$k"
done
ok "dev_sales_rep 权限键授予完成"

ensure_role dev_warehouse_manager "「本地测试」仓管"
for k in erp.inventory.view erp.inventory.receive erp.inventory.adjust erp.inventory.issue erp.inventory.reserve \
         mdm.product.view infra.workflow.task.view infra.notification.view; do
  grant_perm dev_warehouse_manager "$k"
done
ok "dev_warehouse_manager 权限键授予完成"

ensure_role dev_finance_viewer "「本地测试」财务只读"
# ⚠️ 刻意只给 view，不给 post/close/manage_access——这个角色存在的
# 意义就是演示"看得到、改不了"，erp-finance 补种子数据时可以直接用
# 这个角色的测试用户验证写操作会真的 403。
grant_perm dev_finance_viewer erp.finance.view
ok "dev_finance_viewer 权限键授予完成"

echo "── ⑤ 把另外 3 个测试用户分别归到对应部门 + 授予对应角色 ──"
assign_dept() { authed -X POST "$AUTHZ_REST/api/admin/users/$1/department" -d "{\"department_id\":\"$2\"}" >/dev/null; }
grant_role()  { authed -X POST "$AUTHZ_REST/api/admin/users/$1/roles" -d "{\"role_code\":\"$2\"}" >/dev/null; }

SALES_SUB="$(sub_of dev.sales.east)"
WAREHOUSE_SUB="$(sub_of dev.warehouse.south)"
FINANCE_SUB="$(sub_of dev.finance.viewer)"
[ -n "$SALES_SUB" ] && [ -n "$WAREHOUSE_SUB" ] && [ -n "$FINANCE_SUB" ] \
  || die "Casdoor 里找不到某个测试用户——先 make -C components/infra/iam-casdoor seed"

assign_dept "$SALES_SUB" "$EAST_DEPT_ID";       grant_role "$SALES_SUB" dev_sales_rep
assign_dept "$WAREHOUSE_SUB" "$SOUTH_DEPT_ID";  grant_role "$WAREHOUSE_SUB" dev_warehouse_manager
grant_role "$FINANCE_SUB" dev_finance_viewer   # 财务只读不归属具体部门——总纲判据里的"org 维"落在部门树上，财务视角本身是跨部门的

ok "dev.sales.east（sub=$SALES_SUB）→ 华东分部 + dev_sales_rep"
ok "dev.warehouse.south（sub=$WAREHOUSE_SUB）→ 华南分部 + dev_warehouse_manager"
ok "dev.finance.viewer（sub=$FINANCE_SUB）→ dev_finance_viewer（无部门归属）"
echo "   ⚠️ bundle 是各组件每 ~15s 轮询一次拉进内存的——刚写完立刻拿这几个新身份去调别的组件，有真实的竞态窗口，看到 403 先等 18 秒再试"
