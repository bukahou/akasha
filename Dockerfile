# syntax=docker/dockerfile:1

# ---- 构建阶段 ----
FROM golang:1.26 AS build

WORKDIR /src

# 先只拷依赖清单再 download —— 源码变动不会让依赖层缓存失效, 重建快得多
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# CGO_ENABLED=0: 静态链接, 才能跑在 distroless/static 这种没有 libc 的镜像里。
#   本项目走 MySQL 协议 (纯 Go 驱动), 不需要 CGO。
# -trimpath: 去掉构建机的绝对路径, 避免把 /home/xxx 这类信息带进二进制。
# -s -w: 去掉符号表与调试信息, 镜像更小 (代价是无法用 gdb 直接调试, 生产不需要)。
#
# 登录页模板由 go:embed 打进二进制, 因此运行阶段【不需要】拷任何静态资源。
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux go build \
      -trimpath \
      -ldflags="-s -w -X main.version=${VERSION}" \
      -o /out/akasha ./cmd/akasha

# ---- 运行阶段 ----
# distroless/static: 没有 shell、没有包管理器、没有多余二进制 ——
# 攻破进程的人拿不到任何可用工具。对一个持有签名私钥的服务, 这个约束值得。
# 它自带 CA 证书 (调 Google 的 HTTPS 端点需要) 与 /etc/passwd 中的 nonroot 用户。
FROM gcr.io/distroless/static-debian12:nonroot

# 时区: 镜像内为 UTC 且不含 tzdata。
# 生产的 DSN 建议用 loc=UTC 保持全链路一致 —— 只要读写用同一时区就不会出错,
# 但混用 (容器 UTC + DB JST) 会让日志时间与 DB 时间对不上, 排查时很折磨。
ENV TZ=UTC

COPY --from=build /out/akasha /akasha

# 非 root 运行 (uid 65532)。签名私钥经 K8s Secret 以只读方式挂载, 容器内无需写权限。
#
# ⚠️ 挂载私钥时必须让 uid 65532 可读 —— 本地用 0600 的文件直接挂进来会得到
#    "permission denied" 而启动失败 (宿主属主是 uid 1000, 容器用户读不到)。
#    K8s 里的做法: Secret 的 defaultMode 设 0444, 或配 podSecurityContext.fsGroup。
USER nonroot:nonroot

EXPOSE 9100

# 无 shell 镜像里 ENTRYPOINT 必须用 exec 形式 (数组),
# 否则容器收不到 SIGTERM, 优雅关停形同虚设
ENTRYPOINT ["/akasha"]
