# ── Build stage ──────────────────────────────────────────────────────────────
FROM golang:1.21-alpine AS builder
ARG STAGEOPS_NET_BRIDGE
WORKDIR /app

COPY go.mod go.sum ./
RUN export HTTP_PROXY="$STAGEOPS_NET_BRIDGE" HTTPS_PROXY="$STAGEOPS_NET_BRIDGE" \
      http_proxy="$STAGEOPS_NET_BRIDGE" https_proxy="$STAGEOPS_NET_BRIDGE"; \
    for attempt in 1 2 3 4 5; do \
      go mod download && break; \
      if [ "$attempt" -eq 5 ]; then exit 1; fi; \
      sleep 3; \
    done

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o server ./cmd/server/

# ── Runtime stage ─────────────────────────────────────────────────────────────
FROM alpine:3.19
ARG STAGEOPS_NET_BRIDGE
RUN HTTP_PROXY="$STAGEOPS_NET_BRIDGE" HTTPS_PROXY="$STAGEOPS_NET_BRIDGE" \
    http_proxy="$STAGEOPS_NET_BRIDGE" https_proxy="$STAGEOPS_NET_BRIDGE" \
    apk --no-cache add ca-certificates tzdata curl
WORKDIR /app

COPY --from=builder /app/server .
COPY entrypoint.sh .
RUN chmod +x entrypoint.sh

EXPOSE 3000
ENTRYPOINT ["./entrypoint.sh"]
