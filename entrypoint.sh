#!/bin/sh
set -e

# ==============================================================================
# Pingo Appliance - Docker Container Entrypoint
# Runs GoToSocial daemon (if enabled) + Pingo Standalone Server
# ==============================================================================

# Si ENABLE_MASTODON está activado y el binario de GoToSocial existe
if [ "$ENABLE_MASTODON" = "true" ] || [ "$ENABLE_MASTODON" = "1" ]; then
    if [ -x "/usr/bin/gotosocial" ]; then
        echo "🐘 [Appliance] Iniciando GoToSocial en segundo plano..."
        
        GTS_DATA_DIR="/var/lib/p2pt/gotosocial"
        mkdir -p "$GTS_DATA_DIR/storage" "$GTS_DATA_DIR/sqlite" /etc/gotosocial
        
        GTS_CONFIG="/etc/gotosocial/config.yaml"
        PUBLIC_HOST="${DDNS_APPLIANCE_ID:-pingo}.appliances.klitosan.com"
        if [ ! -f "$GTS_CONFIG" ]; then
            cat <<CFG_EOF > "$GTS_CONFIG"
host: "${PUBLIC_HOST}"
protocol: "https"
bind-address: "127.0.0.1"
port: 8080
trusted-proxies:
  - "127.0.0.1/32"
  - "172.16.0.0/12"
  - "192.168.0.0/16"
  - "10.0.0.0/8"
  - "::1"
db-type: "sqlite"
db-address: "${GTS_DATA_DIR}/sqlite/sqlite.db"
storage-backend: "local"
storage-local-base-path: "${GTS_DATA_DIR}/storage"
web-template-base-dir: "/usr/share/gotosocial/web/template/"
web-asset-base-dir: "/usr/share/gotosocial/web/assets/"
media-remote-cache-duration: "48h"
media-local-max-size: "10MiB"
media-remote-max-size: "10MiB"
advanced-rate-limit-requests: 150
instance-expose-peers: true
instance-federation-mode: "blocklist"
accounts-registration-open: false
log-level: "info"
CFG_EOF
            echo "🐘 [Appliance] Configuración GoToSocial inicializada en $GTS_CONFIG"
        fi

        # Iniciar GoToSocial en segundo plano
        /usr/bin/gotosocial --config-path "$GTS_CONFIG" server start >> /var/log/gotosocial.log 2>&1 &
        GTS_PID=$!
        echo "🐘 [Appliance] GoToSocial iniciado con PID $GTS_PID (logs en /var/log/gotosocial.log)"

        # Asegurar auto-creación de cuenta admin y aplicación OAuth si no existen
        (
            sleep 4
            ADMIN_USER="pingo"
            ADMIN_PASS="${ADMIN_PASSWORD:-P1ng0_S3cr3t#2026!}"
            ADMIN_EMAIL="admin@${PUBLIC_HOST}"
            echo "🐘 [Appliance] Comprobando cuenta admin de GoToSocial..."
            /usr/bin/gotosocial --config-path "$GTS_CONFIG" admin account create --username "$ADMIN_USER" --email "$ADMIN_EMAIL" --password "$ADMIN_PASS" >/dev/null 2>&1 || true
            /usr/bin/gotosocial --config-path "$GTS_CONFIG" admin account promote --username "$ADMIN_USER" >/dev/null 2>&1 || true

            # Pre-registrar cliente OAuth para autorización zero-friction
            curl -s -X POST -H "Content-Type: application/json" \
                -d '{"client_name": "PingoAppliance", "redirect_uris": "urn:ietf:wg:oauth:2.0:oob", "scopes": "read write follow"}' \
                http://127.0.0.1:8080/api/v1/apps >/dev/null 2>&1 || true
        ) &
    else
        echo "⚠️  [Appliance] ENABLE_MASTODON=true pero /usr/bin/gotosocial no fue encontrado."
    fi
fi

# Ejecutar el comando principal (p2pt-server)
exec /usr/bin/p2pt-server "$@"
