#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
OUTPUT_DIR="${SCRIPT_DIR}/dist"
mkdir -p "$OUTPUT_DIR"

# 0. Asegurar dependencias del appliance (GoToSocial ARMv6)
GTS_VERSION="${GTS_VERSION:-0.22.1}"
GTS_BIN="${SCRIPT_DIR}/appliance-payload/usr/bin/gotosocial"
if [ ! -f "$GTS_BIN" ]; then
    echo "⬇️  Descargando GoToSocial v${GTS_VERSION} (Linux ARMv6 para Appliance)..."
    mkdir -p "$(dirname "$GTS_BIN")"
    TMP_GTS_TAR=$(mktemp /tmp/gts_XXXXXX.tar.gz)
    curl -fsSL "https://github.com/superseriousbusiness/gotosocial/releases/download/v${GTS_VERSION}/gotosocial_${GTS_VERSION}_linux_armv6.tar.gz" -o "$TMP_GTS_TAR"
    tar -xzf "$TMP_GTS_TAR" -C "$(dirname "$GTS_BIN")" gotosocial
    rm -f "$TMP_GTS_TAR"
    chmod +x "$GTS_BIN"
    echo "✔ GoToSocial v${GTS_VERSION} descargado en appliance-payload/usr/bin/gotosocial"
fi

echo "🔨 Building P2PT / Pingo Standalone Server Binaries..."

# 1. Linux armhf / ARMv6 (Raspberry Pi Zero / Zero W / Pi 1)
echo "📦 Compiling for Linux (ARMv6 / Raspberry Pi Zero)..."
GOOS=linux GOARCH=arm GOARM=6 CGO_ENABLED=0 go build -ldflags="-s -w" -o "$OUTPUT_DIR/p2pt-server-linux-armhf" .

# 2. Linux arm64 (Raspberry Pi 3 / 4 / 5, ARM64 servers)
echo "📦 Compiling for Linux (arm64 / Raspberry Pi 3/4/5)..."
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -ldflags="-s -w" -o "$OUTPUT_DIR/p2pt-server-linux-arm64" .

# 3. Linux amd64
echo "📦 Compiling for Linux (amd64)..."
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s -w" -o "$OUTPUT_DIR/p2pt-server-linux-amd64" .

# 4. Windows amd64
echo "📦 Compiling for Windows (amd64)..."
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s -w" -o "$OUTPUT_DIR/p2pt-server-windows-amd64.exe" .

# 5. macOS Apple Silicon (darwin arm64)
echo "📦 Compiling for macOS (Apple Silicon arm64)..."
GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -ldflags="-s -w" -o "$OUTPUT_DIR/p2pt-server-darwin-arm64" .

# 6. macOS Intel (darwin amd64)
echo "📦 Compiling for macOS (Intel amd64)..."
GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s -w" -o "$OUTPUT_DIR/p2pt-server-darwin-amd64" .

# Generar paquetes APK si nfpm está disponible
NFPM_BIN=$(which nfpm 2>/dev/null || echo "$HOME/go/bin/nfpm")
VERSION="${VERSION:-1.4.0}"
if [ -x "$NFPM_BIN" ] && [ -f "${SCRIPT_DIR}/nfpm.yaml" ]; then
    echo -e "\n📦 Generando paquetes APK para Alpine Linux con nfpm..."
    
    # APK armhf (Pi Zero)
    ARCH="armhf" BIN_PATH="${OUTPUT_DIR}/p2pt-server-linux-armhf" envsubst < "${SCRIPT_DIR}/nfpm.yaml" | \
        "$NFPM_BIN" pkg -f - --packager apk --target "$OUTPUT_DIR/p2pt-server_${VERSION}_armhf.apk"
    
    # APK arm64 (Pi 3/4/5)
    ARCH="arm64" BIN_PATH="${OUTPUT_DIR}/p2pt-server-linux-arm64" envsubst < "${SCRIPT_DIR}/nfpm.yaml" | \
        "$NFPM_BIN" pkg -f - --packager apk --target "$OUTPUT_DIR/p2pt-server_${VERSION}_arm64.apk"
    
    # APK amd64 (x86_64)
    ARCH="x86_64" BIN_PATH="${OUTPUT_DIR}/p2pt-server-linux-amd64" envsubst < "${SCRIPT_DIR}/nfpm.yaml" | \
        "$NFPM_BIN" pkg -f - --packager apk --target "$OUTPUT_DIR/p2pt-server_${VERSION}_x86_64.apk"
fi

echo -e "\n✅ Artefactos generados con éxito en server/dist/:"
ls -lh "$OUTPUT_DIR"
