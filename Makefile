ID      := infra/authz
REPO    := infra-authz
VERSION := $(shell grep -m1 -E '^  version:' component.yaml | awk '{print $$2}')
MAJOR   := $(firstword $(subst ., ,$(VERSION)))
# 项目根：本组件在项目里固定挂在 components/<scope>/<name>/ 下
ROOT    := ../../..

.DEFAULT_GOAL := help
.PHONY: help all check-version test migrate-idempotent dag-check contract-check import-scan module-check docs-check smoke image seed seed-clean

help:  ## 列出所有目标
	@awk 'BEGIN{FS=":.*##"; printf "\n用法: make <目标>\n\n"} \
	     /^[a-zA-Z0-9_-]+:.*##/ {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2} \
	     /^##@/ {printf "\n\033[1m%s\033[0m\n", substr($$0,5)}' $(MAKEFILE_LIST)
	@echo ""

##@ 汇总
all: check-version test migrate-idempotent dag-check contract-check import-scan module-check docs-check  ## 全部门禁（不含要起容器的 smoke / image）

##@ 门禁
check-version:  ## metadata.version、go.mod 的主版本、HEAD 上的 tag 三者一致
	@test -n "$(VERSION)" || { echo "✗ component.yaml 里读不到 metadata.version"; exit 1; }
	@mod="$$(head -1 go.mod | awk '{print $$2}')"; \
	 if [ "$(MAJOR)" -ge 2 ] && [ "$${mod##*/}" != "v$(MAJOR)" ]; then \
	   echo "✗ version $(VERSION) 的主版本是 $(MAJOR)，go.mod 的模块路径应以 /v$(MAJOR) 结尾（实际 $$mod）"; exit 1; fi
	@tags="$$(git tag --points-at HEAD | grep -E '^v?[0-9]+\.[0-9]+\.[0-9]+$$' || true)"; \
	 if [ -n "$$tags" ]; then \
	   for want in "$(VERSION)" "v$(VERSION)"; do \
	     echo "$$tags" | grep -qx "$$want" || { echo "✗ HEAD 有版本 tag（$$(echo $$tags)），但缺 $$want：Go 组件要 $(VERSION) 与 v$(VERSION) 两个 tag 在同一提交"; exit 1; }; \
	   done; \
	   extra="$$(echo "$$tags" | grep -vx -e "$(VERSION)" -e "v$(VERSION)" || true)"; \
	   [ -z "$$extra" ] || { echo "✗ HEAD 上的版本 tag $$extra 与 component.yaml 的 $(VERSION) 不一致"; exit 1; }; \
	 fi
	@echo "✓ version=$(VERSION)（go.mod 主版本一致；HEAD 上没有 tag，或 $(VERSION) 与 v$(VERSION) 都在）"

test:  ## L1–L3 测试。需要 TEST_PG_DSN（指向 brickkit_test_db）；TEST_NATS_URL 可选
	@# 连库测试在没有 TEST_PG_DSN 时 t.Skip，go test 照样打印 ok、退出 0——全部跳过却
	@# 显示通过。所以这里先拦住，大声失败。
	@test -n "$$TEST_PG_DSN" || { echo "✗ 没设 TEST_PG_DSN：连库测试会全部 SKIP 而显示 ok（设法见 AGENTS.md 的 Build and test）"; exit 1; }
	go test ./... -race -count=1

migrate-idempotent:  ## 同一份迁移连跑两次都成功。需要 PG_HOST PG_PORT PG_DATABASE PG_USER PG_PASSWORD PG_SCHEMA（以 infra_authz_rw 登录）
	@# 例：PG_HOST=localhost PG_PORT=5432 PG_DATABASE=brickkit_test_db PG_USER=infra_authz_rw
	@#     PG_PASSWORD=… PG_SCHEMA=infra_authz make migrate-idempotent
	@mkdir -p build && go build -o build/migrate-probe ./backend/cmd/migrate
	@build/migrate-probe up && build/migrate-probe up && echo "✓ 迁移幂等"

dag-check:  ## 没有任何依赖：所有组件都靠本组件的 bundle 判权限，它自己不调任何人
	@n="$$(python3 -c 'import yaml; m = yaml.safe_load(open("component.yaml")); print(len((m.get("dependencies") or {}).get("components") or []))')"; \
	 [ "$$n" = 0 ] || { echo "✗ dependencies.components 应为空（实际 $$n 条）：authz 一旦依赖别的组件，那个组件起不来时所有组件的受保护路由都跟着 503"; exit 1; }
	@echo "✓ 无依赖，无环"

contract-check:  ## proto 只增不改（buf lint + buf breaking，对比上一个发布 tag；还没有发布过就对比 main）
	@# 对比 main 抓不住已经提交到 main 上的破坏性改动（在 main 上工作时等于自己比自己），
	@# 所以对比上一个组件版本 tag（契约包的 gen/* tag 不算）。
	buf lint
	@base="$$(git describe --tags --abbrev=0 --exclude 'gen/*' 2>/dev/null)"; \
	 against="$${base:+.git#tag=$$base}"; against="$${against:-.git#branch=main}"; \
	 echo "buf breaking --against '$$against'"; buf breaking --against "$$against"

import-scan:  ## 只 import SDK 与自己；别的组件只能用它发布的 gen/ 契约包
	@# go list 失败（模块解析不了、编译错误）时必须失败：先单独取输出、查退出码，
	@# 再过滤。管道里直接接 grep 会吞掉 go list 的退出码，什么都没扫到也打印 ✓。
	@deps="$$(go list -deps ./...)" || { echo "✗ go list -deps ./... 失败，没法扫 import"; exit 1; }; \
	 bad="$$(printf '%s\n' "$$deps" | awk '/^github\.com\/brickKit\// \
	         && !/^github\.com\/brickKit\/($(REPO)\/v$(MAJOR)|be-sdk-go)(\/|$$)/ \
	         && !/^github\.com\/brickKit\/[^\/]+\/gen\//')"; \
	 if [ -n "$$bad" ]; then \
	   echo "✗ import 了别的组件的代码："; echo "$$bad"; exit 1; fi; \
	 echo "✓ 无组件间 import"

module-check:  ## 模块能被合进外壳：入口签名对、零 os.Getenv、零进程级初始化、栈合规
	@# 只扫 backend/module 与 backend/internal（会被合进外壳的部分）；backend/cmd 是
	@# 独立运行的装配代码，不在范围内。先去掉行内 // 注释再 grep，免得解释"为什么
	@# 不许 log.Fatal"的注释把自己判成违规；_test.go 不扫（测试自己开库是测试设施）。
	@grep -qE 'func New\(ctx context\.Context, rt \*besdk\.Runtime\) \(\*besdk\.Module, error\)' \
	   backend/module/module.go || { echo "✗ module.New 的签名不对"; exit 1; }
	@bad=""; \
	 for f in $$(find backend/module backend/internal -name '*.go' ! -name '*_test.go'); do \
	   hit="$$(sed 's://.*::' "$$f" | grep -nE 'os\.Getenv|os\.LookupEnv|os\.Environ')"; \
	   [ -n "$$hit" ] && bad="$$bad$$f: $$hit\n"; \
	 done; \
	 if [ -n "$$bad" ]; then \
	   echo "✗ 模块代码读了进程环境变量（进外壳后成员互相覆盖，不报错）："; printf '%b' "$$bad"; exit 1; fi
	@bad=""; \
	 for f in $$(find backend/module backend/internal -name '*.go' ! -name '*_test.go'); do \
	   hit="$$(sed 's://.*::' "$$f" | grep -nE 'log\.Fatal|os\.Exit|signal\.Notify|otel\.SetTracerProvider|promauto\.|prometheus\.MustRegister|gin\.New\(|gin\.Default\(|gin\.SetMode|sql\.Open|net\.Listen')"; \
	   [ -n "$$hit" ] && bad="$$bad$$f: $$hit\n"; \
	 done; \
	 if [ -n "$$bad" ]; then \
	   echo "✗ 模块碰了进程级的东西或自己装配："; printf '%b' "$$bad"; exit 1; fi
	@deps="$$(go list -deps ./backend/module/... ./backend/internal/...)" || { echo "✗ go list -deps 失败，没法核对依赖栈"; exit 1; }; \
	 bad="$$(printf '%s\n' "$$deps" | awk '/labstack\/echo|gofiber\/fiber|go-chi\/chi|jinzhu\/gorm|gorm\.io|lib\/pq/')"; \
	 if [ -n "$$bad" ]; then \
	   echo "✗ 用了锁定栈之外的库："; echo "$$bad"; exit 1; fi
	@echo "✓ 入口签名对、零 os.Getenv、零进程级初始化、栈合规"

docs-check:  ## 清单与文档的严格 lint（= 项目根 make docs-check ID=$(ID)）
	@cd $(ROOT) && brickkit lint --strict $(ID)

##@ 要起容器的检查（在项目里跑）
smoke:  ## 项目能为本组件生成部署文件（brickkit up --dry-run）
	@cd $(ROOT) && brickkit up --dry-run >/dev/null && echo "✓ smoke：up --dry-run 通过"

image:  ## brickkit build 本组件，并确认镜像里有 sh + wget（健康检查经 /bin/sh 调 wget）
	@cd $(ROOT) && brickkit build $(ID)
	@docker run --rm --entrypoint sh $(REPO):$(VERSION) -c 'wget --version >/dev/null && test -f /app/component.yaml' \
	  && echo "✓ 镜像 $(REPO):$(VERSION) 里有 sh + wget + component.yaml"

##@ 本地开发数据（只给本地 / 演示用，不进部署与 CI）
seed:  ## 给种子用户授权：dev.superuser 全权限角色、部门树、三个岗位角色（幂等）。要求本组件已起、iam-casdoor 的种子用户已建
	@bash scripts/seed.sh

seed-clean:  ## 撤销 seed 建的角色、授权与部门树
	@bash scripts/seed-clean.sh
