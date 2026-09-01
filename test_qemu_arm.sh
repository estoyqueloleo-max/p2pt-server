#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DIST_DIR="${SCRIPT_DIR}/dist"

echo "🥧 Iniciando Prueba 5: Emulación Raspberry Pi Zero (ARMv6) con QEMU..."

if [ ! -f "${DIST_DIR}/p2pt-server_1.0.0_armhf.apk" ]; then
    echo "🔨 Compilando artefactos..."
    bash "${SCRIPT_DIR}/build.sh"
fi

echo "📦 Probando instalación de paquete APK y ejecución del binario ARMv6 en Alpine ARM emulado..."

docker run --rm --platform linux/arm/v6 \
  -v "${DIST_DIR}:/dist:ro" \
  alpine:latest /bin/sh -c '
    set -e
    echo "1. Arquitectura de CPU emulada:"
    uname -m
    
    echo "2. Instalando paquete APK generado para Raspberry Pi Zero..."
    apk add --allow-untrusted /dist/p2pt-server_1.0.0_armhf.apk
    
    echo "3. Verificando binario y servicio OpenRC..."
    ls -l /usr/bin/p2pt-server /etc/init.d/p2pt
    
    echo "4. Iniciando p2pt-server en segundo plano (ARMv6)..."
    /usr/bin/p2pt-server -no-upnp -port=9000 -turn-port=3478 -public-ip=127.0.0.1 > /tmp/server.log 2>&1 &
    SERVER_PID=$!
    
    sleep 2
    
    echo "5. Verificando logs de arranque en ARMv6:"
    head -n 20 /tmp/server.log
    
    echo "6. Comprobando respuesta HTTP / JSON de configuración..."
    apk add --no-cache curl bind-tools >/dev/null 2>&1
    
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:9000/)
    echo "HTTP Status Code: $HTTP_CODE"
    
    if [ "$HTTP_CODE" -eq 200 ]; then
        echo "✅ Dashboard HTTP responde correctamente en ARMv6 (HTTP 200)!"
    else
        echo "❌ Error en respuesta HTTP: $HTTP_CODE"
        exit 1
    fi
    
    echo "7. Deteniendo proceso emulado..."
    kill $SERVER_PID 2>/dev/null || true
    echo "🏆 PRUEBA 5 COMPLETADA CON ÉXITO: El binario y APK ARMv6 funcionan al 100% para Raspberry Pi Zero!"
'
