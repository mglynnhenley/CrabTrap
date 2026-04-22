# Multi-stage build: web UI -> Go binary -> minimal runtime image.

FROM node:20-alpine AS web-builder
WORKDIR /src/web
COPY web/package.json web/package-lock.json* ./
RUN npm install
COPY web/ ./
RUN npm run build

FROM golang:1.26-alpine AS go-builder
WORKDIR /src
RUN apk add --no-cache git
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN rm -rf cmd/gateway/web && mkdir -p cmd/gateway/web/dist
COPY --from=web-builder /src/web/dist/ ./cmd/gateway/web/dist/
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /out/gateway ./cmd/gateway

FROM alpine:3.20
RUN apk add --no-cache ca-certificates wget
WORKDIR /app
COPY --from=go-builder /out/gateway /app/gateway
EXPOSE 8080 8081
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8081/health || exit 1
ENTRYPOINT ["/app/gateway"]
CMD ["-config", "/app/config/gateway.yaml"]
