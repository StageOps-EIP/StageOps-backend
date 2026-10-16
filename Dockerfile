# syntax=docker/dockerfile:1

# ── Build stage ──────────────────────────────────────────────────────────────
FROM golang:1.27.2-alpine AS builder
WORKDIR /app

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download

COPY . .
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux go build \
      -trimpath \
      -ldflags="-s -w" \
      -o /out/server ./cmd/server/

# ── Runtime stage ─────────────────────────────────────────────────────────────
FROM alpine:3.22

RUN apk --no-cache add ca-certificates curl jq tzdata \
    && addgroup -S stageops \
    && adduser -S -G stageops -H -h /app stageops
WORKDIR /app

COPY --from=builder --chown=stageops:stageops /out/server ./server
COPY --chown=stageops:stageops entrypoint.sh ./entrypoint.sh
COPY --chown=stageops:stageops deploy/migrate-theatre-container.sh ./migrate-theatre.sh
RUN chmod 0555 ./server ./entrypoint.sh ./migrate-theatre.sh

EXPOSE 3000

USER stageops

HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=5 \
  CMD curl --fail --silent http://127.0.0.1:3000/api/health/ready >/dev/null || exit 1

ENTRYPOINT ["./entrypoint.sh"]
