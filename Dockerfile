# ── Build stage ──────────────────────────────────────────────────────────────
FROM golang:1.22-alpine AS builder

# CGO is required for go-sqlite3
RUN apk add --no-cache gcc musl-dev sqlite-dev

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=1 GOOS=linux go build -ldflags="-s -w -linkmode external -extldflags -static" -o authsentry .

# ── Runtime stage ─────────────────────────────────────────────────────────────
FROM alpine:3.19

RUN apk add --no-cache ca-certificates tzdata

# Non-root user
RUN addgroup -S sentry && adduser -S sentry -G sentry
USER sentry

WORKDIR /data

COPY --from=builder /build/authsentry /usr/local/bin/authsentry

VOLUME ["/data"]

ENTRYPOINT ["authsentry"]
CMD ["--help"]
