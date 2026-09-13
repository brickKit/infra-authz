# ⚠️ 基底必须带 /bin/sh 加 wget 或 curl（§12.3.7）。
# 平台生成的健康检查是 CMD-SHELL，FROM scratch / distroless 连 shell 都没有。
FROM golang:1.25-alpine AS build
WORKDIR /src
RUN apk add --no-cache git
# ⚠️ gen/infra/authz 是本仓库自己嵌套的 go module，go.mod 里用本地相对
# 路径 replace 指向它（阶段四调研记录 04 §13）——go mod download 解析
# replace 时必须已经能读到这个子目录自己的 go.mod，所以不能像常见写法
# 那样只先 COPY go.mod go.sum 再 download：本地 replace 没有远程校验和
# 可下载，必须整个源码树都在场才能解析。
COPY . .
RUN go mod download
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/server  ./backend/cmd/server \
 && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/migrate ./backend/cmd/migrate

FROM alpine:3.20
RUN apk add --no-cache wget ca-certificates tzdata
WORKDIR /app
COPY --from=build /out/server  /app/server
COPY --from=build /out/migrate /app/migrate
COPY migrations /app/migrations
# ⚠️ 端口不是平台注入的（§13.8.1）：RunStandalone 自己读这份文件的
# deployment.port/extraPorts 来决定监听哪个端口，漏拷会启动即报错退出。
COPY component.yaml /app/component.yaml
EXPOSE 8223 9223
ENTRYPOINT ["/app/server"]
