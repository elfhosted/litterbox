# litterbox — multi-stage build → minimal alpine runtime.
#
# Stage 1 builds the Go binary with embedded web/ assets (embed.FS).
# Stage 2 is a stripped alpine image carrying only the binary and the
# CA certs needed for TLS to api.real-debrid.com.
#
# Pinned to golang:1.25-alpine to match the project's go.mod.

FROM golang:1.25-alpine AS build
WORKDIR /src

# Cache module downloads independently of source changes.
COPY go.mod ./
RUN go mod download

# Source.
COPY . .

# Build a static binary. CGO_ENABLED=0 + -ldflags='-s -w' keeps the
# image lean; the embedded web/ directory rides along via the
# embed.FS in internal/server.
RUN CGO_ENABLED=0 GOOS=linux \
    go build -trimpath -ldflags='-s -w' -o /out/litterbox .

# Runtime stage.
FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata && \
    addgroup -g 1000 litterbox && \
    adduser -D -u 1000 -G litterbox -s /sbin/nologin litterbox
COPY --from=build /out/litterbox /usr/local/bin/litterbox
USER litterbox
EXPOSE 8080
ENV LISTEN=:8080
ENTRYPOINT ["/usr/local/bin/litterbox"]
