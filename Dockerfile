# syntax=docker/dockerfile:1

# builder: identical Go toolchain to the local machine
FROM docker.m.daocloud.io/library/golang:1.26.3-bookworm AS builder
WORKDIR /src
COPY . .
ENV CGO_ENABLED=0 \
    GOTOOLCHAIN=local \
    GOPROXY=https://goproxy.cn,direct \
    GOSUMDB=sum.golang.google.cn
RUN go build -mod=vendor -o /out/task039-webhook .

# runtime: minimal image
FROM docker.m.daocloud.io/library/alpine:3.20
RUN apk add --no-cache ca-certificates
WORKDIR /app
COPY --from=builder /out/task039-webhook /task039-webhook
EXPOSE 8080
ENTRYPOINT ["/task039-webhook"]
CMD ["server", "--addr", ":8080"]
