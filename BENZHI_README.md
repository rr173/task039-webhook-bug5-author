# Benzhi 评测镜像说明

本项目是一个纯标准库 Go Webhook 接收服务，提供 HMAC-SHA256 验签、事件幂等去重、同步投递重试、死信记录和 HTTP 查询接口。

## 本地构建、运行和测试

```bash
GOTOOLCHAIN=local go build ./...
GOTOOLCHAIN=local go run . --smoke-test
GOTOOLCHAIN=local go test ./...
GOTOOLCHAIN=local go vet ./...
```

启动 HTTP 服务：

```bash
GOTOOLCHAIN=local go run . server --addr :8080
```

## Benzhi Docker 镜像

`build_benzhi_docker.sh` 固定使用 `benzhi.Dockerfile` 构建评测镜像，参数依次为镜像名和平台，默认值为 `my-project` 与 `linux/amd64`。

```bash
bash ./build_benzhi_docker.sh go-task039-webhook:amd64 linux/amd64
bash ./build_benzhi_docker.sh go-task039-webhook:arm64 linux/arm64
docker run --rm go-task039-webhook:amd64 go version
```

镜像启动后默认进入 Bash，便于在容器内执行构建、测试和自检命令；项目自身的运行时镜像仍由 `Dockerfile` 提供。
