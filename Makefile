IMAGE   := brickenterprise/infra-authz
VERSION := $(shell grep -E '^\s+version:' component.yaml | head -1 | awk '{print $$2}')

.DEFAULT_GOAL := help
.PHONY: help all check-version test image migrate-idempotent dag-check contract-check import-scan module-check docs-check smoke

help:  ## 列出所有目标
	@awk 'BEGIN{FS=":.*##"; printf "\n用法: make <目标>\n\n"} \
	     /^[a-zA-Z0-9_-]+:.*##/ {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2} \
	     /^##@/ {printf "\n\033[1m%s\033[0m\n", substr($$0,5)}' $(MAKEFILE_LIST)
	@echo ""

##@ 汇总
all: check-version test image migrate-idempotent dag-check contract-check import-scan module-check docs-check  ## 8 个门禁（不含 smoke，它要真起容器）

##@ 9 个门禁
check-version:  ## component.yaml 的 version 与 git tag 不许分叉（§9.1 两个真相源）
	@tag="$$(git describe --tags --exact-match 2>/dev/null || true)"; \
	 if [ -n "$$tag" ] && [ "$$tag" != "v$(VERSION)" ]; then \
	   echo "✗ git tag $$tag 与 component.yaml 的 $(VERSION) 不一致"; exit 1; fi; \
	 echo "✓ version=$(VERSION)"

test:  ## 需要 TEST_PG_DSN 与 TEST_NATS_URL（可选，缺省走 nats.DefaultURL）
	go test ./... -race -count=1

image:  ## 建镜像并确认里面有 sh + wget（§12.3.7 健康检查需要）
	docker build -t $(IMAGE):$(VERSION) .
	@# 镜像里必须有 /bin/sh + wget，否则平台的 CMD-SHELL 健康检查永远失败
	@docker run --rm --entrypoint sh $(IMAGE):$(VERSION) -c 'wget --version >/dev/null' \
	  && echo "✓ 镜像里有 sh + wget"

migrate-idempotent:  ## 同一份迁移连跑两次都必须成功（§13.3 铁律五）
	@# 需要 DATABASE_HOST/PORT/USER/PASSWORD/NAME + PG_SCHEMA（平台真实注入
	@# 的分离变量契约）。本地跑迁移要用 postgres 超级用户（不是
	@# infra_authz_rw）：建分区之类的 DDL 需要建表权限。
	@go build -o /tmp/infra-authz-migrate-probe ./backend/cmd/migrate
	@/tmp/infra-authz-migrate-probe up && /tmp/infra-authz-migrate-probe up && echo "✓ 迁移幂等"

dag-check:  ## 强依赖图无环（§4.2）。零强依赖，天然无环
	@if ! grep -qE '^\s*components:\s*\[\]' component.yaml; then \
	   echo "✗ infra-authz 强依赖必须为空（mdm/org 是弱依赖，阶段五才建边）"; exit 1; fi
	@echo "✓ 无强依赖，无环"

contract-check:  ## 禁破坏性变更（§8.5、决策 33）
	buf lint
	buf breaking --against '.git#branch=main'

import-scan:  ## 铁律六：不许 import 任何其他组件仓库（§13.3）
	@bad="$$(go list -deps ./... 2>/dev/null | grep -E '^github.com/brickKit/' \
	         | grep -vE '^github.com/brickKit/(infra-authz|be-sdk-go)(/|$$)' || true)"; \
	 if [ -n "$$bad" ]; then \
	   echo "✗ 铁律六违规，import 了其他组件仓库："; echo "$$bad"; exit 1; fi; \
	 echo "✓ 无组件间 import"

module-check:  ## 铁律七：模块能被合进外壳（§12.5、§13.3 铁律七）
	@# ⚠️ 只扫 backend/module 与 backend/internal（能被合进外壳的部分）：
	@# backend/cmd 是装配用途，允许 os.Getenv；cmd/migrate 依赖
	@# golang-migrate 自带的 postgres 驱动（内部用 lib/pq，是它自己的
	@# 实现细节，只在一次性迁移容器里跑）——banned-libs 检查缩小到
	@# module+internal，不扫 cmd。
	@#
	@# 检查前用 sed 去掉行内 // 注释再 grep：这个代码库风格本来就大量写
	@# "⚠️ 不许 X"这类解释性注释，不去注释会把自己判成违规。同时排除
	@# _test.go：连库测试用 os.Getenv("TEST_PG_DSN")/sql.Open 是测试
	@# 基础设施，不是模块运行时代码。
	@grep -qE 'func New\(ctx context\.Context, rt \*besdk\.Runtime\) \(\*besdk\.Module, error\)' \
	   backend/module/module.go || { echo "✗ module.New 签名与 §12.5.1 不一致"; exit 1; }
	@bad=""; \
	 for f in $$(find backend/module backend/internal -name '*.go' ! -name '*_test.go'); do \
	   hit="$$(sed 's://.*::' "$$f" | grep -nE 'os\.Getenv|os\.LookupEnv')"; \
	   [ -n "$$hit" ] && bad="$$bad$$f: $$hit\n"; \
	 done; \
	 if [ -n "$$bad" ]; then \
	   echo "✗ 模块代码里读了进程环境变量（22 个模块会互相顶掉，不报错）："; \
	   printf '%b' "$$bad"; exit 1; fi
	@bad=""; \
	 for f in $$(find backend/module backend/internal -name '*.go' ! -name '*_test.go'); do \
	   hit="$$(sed 's://.*::' "$$f" | grep -nE 'log\.Fatal|os\.Exit|signal\.Notify|otel\.SetTracerProvider|promauto\.|prometheus\.MustRegister|gin\.New\(|gin\.Default\(|sql\.Open')"; \
	   [ -n "$$hit" ] && bad="$$bad$$f: $$hit\n"; \
	 done; \
	 if [ -n "$$bad" ]; then \
	   echo "✗ 模块碰了进程级的东西或自己装配（§12.5.2）："; printf '%b' "$$bad"; exit 1; fi
	@bad="$$(go list -deps ./backend/module/... ./backend/internal/... 2>/dev/null \
	         | grep -E 'labstack/echo|gofiber/fiber|go-chi/chi|jinzhu/gorm|gorm\.io|lib/pq' || true)"; \
	 if [ -n "$$bad" ]; then \
	   echo "✗ 用了 §12.4 禁掉的库："; echo "$$bad"; exit 1; fi
	@echo "✓ 铁律七：入口签名对、零 os.Getenv、零进程级 init、栈合规"

docs-check:  ## 四份文档结构检查（总纲 §4 SOP-D）
	@bash ../../../infra/scripts/docs-check.sh infra-authz

smoke:  ## 原则一：只装这一个组件就能起来（§1.5、§3.11 第 8 条）
	@# brickkit 不向上找 brickkit.yaml，必须从装配仓库根目录跑——本组件
	@# 固定挂在 components/infra/authz 下，根目录固定是 ../../..
	@(cd ../../.. && brickkit up --dry-run >/dev/null) && echo "✓ smoke（完整版见 make tier0）"
