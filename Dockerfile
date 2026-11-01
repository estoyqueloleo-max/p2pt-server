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
# Stage: Build Phanpy client statically from official source
# ------------------------------------------------------------------------------
FROM node:22-alpine AS phanpy-builder
WORKDIR /build
RUN apk add --no-cache git
RUN git clone --depth 1 https://github.com/cheeaun/phanpy.git .
RUN npm ci || npm install
ENV PHANPY_CLIENT_NAME="Pingo Fediverse (Phanpy)"
RUN npm run build

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
RUN mkdir -p /var/lib/p2pt/repos /var/lib/p2pt/web /var/lib/p2pt/phanpy /usr/share/pingo/web /usr/share/pingo/phanpy /etc/p2pt /var/log

# Copiar binario compilado
COPY --from=builder /p2pt-server /usr/bin/p2pt-server

# Copiar frontend estático tanto a /usr/share/pingo/web (inmutable, no afectado por volumen) como a /var/lib/p2pt/web
COPY dist* /usr/share/pingo/web/
COPY dist* /var/lib/p2pt/web/

# Copiar cliente web Phanpy compilado en la etapa multistage
COPY --from=phanpy-builder /build/dist /usr/share/pingo/phanpy/
COPY --from=phanpy-builder /build/dist /var/lib/p2pt/phanpy/

# Copiar GoToSocial oficial (binario y plantillas web) desde la imagen oficial multi-arquitectura
COPY --from=superseriousbusiness/gotosocial:latest /gotosocial/gotosocial /usr/bin/gotosocial
COPY --from=superseriousbusiness/gotosocial:latest /gotosocial/web /usr/share/gotosocial/web

# Copiar script de arranque (entrypoint) que orquesta gotosocial + p2pt-server
COPY entrypoint.sh /usr/bin/entrypoint.sh
RUN chmod +x /usr/bin/entrypoint.sh

# Variables de entorno predeterminadas
ENV PORT=443 \
    TURN_PORT=3478 \
    MIN_RELAY_PORT=7000 \
    MAX_RELAY_PORT=7010 \
    ENABLE_UPNP=false \
    ENABLE_MDNS=false \
    ENABLE_GIT=true \
    GIT_DIR=/var/lib/p2pt/repos \
    WEB_DIR=/usr/share/pingo/web \
    PHANPY_DIR=/usr/share/pingo/phanpy

# Persistencia para repositorios Git y base de datos/tokens
VOLUME ["/var/lib/p2pt"]

# Puertos expuestos:
# 443: Web Dashboard, PeerJS WebSocket Signaling, Git Smart HTTP
# 3478: TURN/STUN (UDP y TCP)
EXPOSE 443/tcp 3478/udp 3478/tcp

WORKDIR /var/lib/p2pt

ENTRYPOINT ["/usr/bin/entrypoint.sh"]
