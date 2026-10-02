# 基础镜像必须带 /bin/sh 与 wget：平台的健康检查是 CMD-SHELL 调 wget，
# scratch / distroless 里没有 shell，组件日志写着就绪、平台却一直报 unhealthy。
FROM golang:1.25-alpine AS build
WORKDIR /src
RUN apk add --no-cache git
# 先拷整个源码树再 go mod download：契约包 gen/infra/authz 是本仓库里的嵌套
# 模块，go.mod 用本地 replace 指向它，只拷 go.mod/go.sum 时这个目录还不在，
# download 解析不了 replace。
COPY . .
RUN go mod download
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/server  ./backend/cmd/server \
 && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/migrate ./backend/cmd/migrate

FROM alpine:3.20
RUN apk add --no-cache wget ca-certificates tzdata
WORKDIR /app
COPY --from=build /out/server  /app/server
# 迁移文件已嵌进 migrate 二进制（migrations/embed.go），不用另拷 .sql。
# component.yaml 的 migration.command 是 ./migrate up，所以放在 WORKDIR 下。
COPY --from=build /out/migrate /app/migrate
# RunStandalone 从工作目录的 component.yaml 读 deployment.port / extraPorts
# 决定监听哪些端口；漏拷这一份，容器启动即退出。
COPY component.yaml /app/component.yaml
EXPOSE 8223 9223
ENTRYPOINT ["/app/server"]
