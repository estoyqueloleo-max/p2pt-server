# ==============================================================================
# Pingo Appliance - Cloud & Standalone Docker Container
# ==============================================================================
# Multi-stage build:
# Stage 1: Build p2pt-server statically with Go
# Stage 2: Minimal Alpine Linux runtime with git, sqlite, ca-certificates
# ==============================================================================

FROM golang:1.24-alpine AS builder

WORKDIR /src

# Instalar dependencias para compilar
RUN apk add --no-cache git ca-certificates

# Cachear módulos Go
COPY go.mod go.sum ./
RUN go mod download

# Compilar binario estático para la arquitectura destino
COPY . .
ARG TARGETOS TARGETARCH
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} \
    go build -ldflags="-s -w" -o /p2pt-server .

# ------------------------------------------------------------------------------
# Runtime Image
# ------------------------------------------------------------------------------
FROM alpine:3.19

# Instalar utilidades esenciales para Smart HTTP Git y persistencia
RUN apk add --no-cache \
    ca-certificates \
    curl \
    git \
    sqlite \
    tzdata

# Estructura de directorios estándar de la appliance
RUN mkdir -p /var/lib/p2pt/repos /etc/p2pt /var/log

# Copiar binario compilado
COPY --from=builder /p2pt-server /usr/bin/p2pt-server

# Variables de entorno predeterminadas
ENV PORT=443 \
    TURN_PORT=3478 \
    ENABLE_UPNP=false \
    ENABLE_MDNS=false \
    ENABLE_GIT=true \
    GIT_DIR=/var/lib/p2pt/repos

# Persistencia para repositorios Git y base de datos/tokens
VOLUME ["/var/lib/p2pt"]

# Puertos expuestos:
# 443: Web Dashboard, PeerJS WebSocket Signaling, Git Smart HTTP
# 3478: TURN/STUN (UDP y TCP)
EXPOSE 443/tcp 3478/udp 3478/tcp

WORKDIR /var/lib/p2pt

ENTRYPOINT ["/usr/bin/p2pt-server"]
