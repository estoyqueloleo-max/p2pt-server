#!/usr/bin/env bash
set -e

# ==============================================================================
# Script de construcción y publicación Docker multi-arquitectura para Pingo
# Soporta: linux/amd64 (PC/Servidores) y linux/arm64 (Raspberry Pi 3/4/5)
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
SERVER_DIR="${SCRIPT_DIR}"
REGISTRY="${DOCKER_REGISTRY:-192.168.1.4:5000}"
IMAGE_NAME="${DOCKER_IMAGE_NAME:-pingo/server}"
BUILDER_NAME="pingo-multiarch-builder"

# Detectar versión del tag de git o usar v1.4.2 por defecto
VERSION=$(git -C "${SCRIPT_DIR}/.." describe --tags --abbrev=0 2>/dev/null || echo "v1.4.2")

echo "🚀 Iniciando build multi-arquitectura para Pingo Server [${VERSION}]..."
echo "📍 Registro destino: ${REGISTRY}/${IMAGE_NAME}"

# 1. Asegurar soporte de binfmt para emulación QEMU en el host
if ! docker buildx ls | grep -q "linux/arm64"; then
    echo "🔧 Registrando emuladores binfmt para arquitecturas ARM..."
    docker run --privileged --rm tonistiigi/binfmt --install all >/dev/null 2>&1 || true
fi

# 2. Configurar Buildx Builder con soporte para registros HTTP inseguros
if ! docker buildx inspect "${BUILDER_NAME}" >/dev/null 2>&1; then
    echo "🔧 Creando builder '${BUILDER_NAME}' con soporte para ${REGISTRY}..."
    TMP_CONFIG=$(mktemp)
    cat <<EOF > "$TMP_CONFIG"
[registry."${REGISTRY}"]
  http = false
  insecure = true
EOF
    docker buildx create --name "${BUILDER_NAME}" --config "$TMP_CONFIG" --use --bootstrap
    rm -f "$TMP_CONFIG"
else
    docker buildx use "${BUILDER_NAME}"
fi

# 3. Preparar frontend estático en el contexto de construcción si existe
if [ -d "${SCRIPT_DIR}/../dist" ]; then
    echo "📦 Sincronizando frontend web compilado (dist/) en contexto del appliance..."
    rm -rf "${SERVER_DIR}/dist"
    cp -r "${SCRIPT_DIR}/../dist" "${SERVER_DIR}/dist"
fi

# 4. Compilar y pushear para linux/amd64 y linux/arm64
echo "🔨 Compilando y subiendo imágenes para linux/amd64 y linux/arm64..."
docker buildx build \
    --platform linux/amd64,linux/arm64 \
    -t "${REGISTRY}/${IMAGE_NAME}:${VERSION}" \
    -t "${REGISTRY}/${IMAGE_NAME}:latest" \
    -f "${SERVER_DIR}/Dockerfile" "${SERVER_DIR}" \
    --push

echo -e "\n🎉 ¡Imágenes Docker construidas y publicadas con éxito!"
echo "   - ${REGISTRY}/${IMAGE_NAME}:${VERSION}"
echo "   - ${REGISTRY}/${IMAGE_NAME}:latest"
