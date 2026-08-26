# 🌐 Pingo Standalone Server (PeerJS + Pion TURN/STUN)

Servidor ejecutable independiente "Todo en Uno" desarrollado en Go para autoalojamiento doméstico o en VPS de la infraestructura de **Pingo**.

Elimina la necesidad de instalar Docker, Node.js o configurar Coturn por separado: en un único binario ligero (~15 MB) incluye el **Servidor de Señalización PeerJS** (WebSockets), el **Servidor de Relé STUN/TURN** (`pion/turn`), **Auto-configuración UPnP para routers**, **Sincronización automática con DuckDNS** y un **Asistente Web/CLI interactivo**.

---

## ✨ Características

- ⚡ **Binario Único sin Dependencias**: Compilado en Go estático.
- 📡 **Señalización PeerJS Integrada**: Conexiones WebSocket nativas para intercambio de SDP/ICE y presencia.
- 🔄 **Relé TURN/STUN Integrado**: Servidor UDP de alto rendimiento con `pion/turn` para atravesar NATs simétricos y redes móviles (4G/5G).
- 🔌 **Auto-Apertura UPnP & Diagnóstico CGNAT**: Detecta tu router automáticamente, abre los puertos UDP/TCP sin tocar el panel del router y te avisa si tu operadora tiene CGNAT activo.
- 🦆 **Integración con DuckDNS (`duckdns.org`)**: Sincronización automática de tu IP pública dinámica con tu subdominio gratuito cada 10 minutos.
- 🧙 **Asistente Interactivo (CLI & Web)**: Asistente paso a paso en terminal (`-wizard`) o directamente desde el panel web de control.
- 📲 **Auto-Vinculación por QR / URL**: Muestra en la consola de terminal y en la web un código QR interactivo y enlace directo para vincular la app Pingo en 1 clic.
- ⚙️ **Multiplataforma**: Binarios listos para Linux (x86_64 y ARM64 / Raspberry Pi), Windows (`.exe`) y macOS (Apple Silicon e Intel).
- 🔒 **Soporte TLS / WSS**: Compatible con certificados SSL directos o detrás de proxys inversos (Nginx, Caddy, Cloudflare Tunnel).

---

## 🚀 Inicio Rápido

### 1. Descarga o Compila el Binario

```bash
cd server
go build -o pingo-server .
```

*(O ejecuta `./build.sh` para compilar todas las arquitecturas).*

---

### 2. Ejecutar con el Asistente Paso a Paso (Recomendado para principiantes)

```bash
./pingo-server -wizard
```
El asistente te preguntará en terminal:
1. Tu subdominio de DuckDNS (si tienes uno, ej. `mi-nodo-pingo`).
2. Tu Token privado de DuckDNS (lo verifica al instante).
3. Puertos deseados y auto-apertura UPnP en router.

---

### 3. Ejecución Directa

```bash
# Modo básico con auto-detección de IP y auto-UPnP
./pingo-server

# Modo con DuckDNS automático
./pingo-server -duck-domain="mi-nodo-pingo" -duck-token="tu-token-aqui"
```

Al arrancar, el servidor:
1. Comprueba si el router local soporta **UPnP** y abre los puertos `3478/UDP` y `9000/TCP`.
2. Diagnostica si tu conexión tiene **CGNAT** comparando la IP del router con la IP pública exterior.
3. Si configuraste DuckDNS, sincroniza tu subdominio inmediatamente y mantiene la IP actualizada en segundo plano.
4. Muestra en terminal el **código QR de emparejamiento**, el enlace y el enlace al **Panel Web**.

---

## 🖥️ Panel Web de Control y Diagnóstico

Abre en tu navegador: `http://localhost:9000/` (o tu IP local / dominio):

* **Código QR y botón de 1-clic**: Para abrir Pingo en tu móvil con este servidor ya configurado.
* **Asistente DuckDNS**: Permite introducir tu subdominio y token directamente en la web, probar la conexión y actualizar la URL pública sin reiniciar el servidor.
* **Tarjeta de Diagnóstico UPnP y CGNAT**: Estado del router, IP pública detectada y botón para re-escanear puertos.
* **Métricas en tiempo real**: Clientes WebRTC conectados y estado de los puertos.
* **JSON de Configuración**: Para importar manualmente en Ajustes de Pingo si se desea.

---

## ⚙️ Parámetros de Configuración (Flags y Variables de Entorno)

| Flag | Variable de Entorno | Valor por Defecto | Descripción |
| :--- | :--- | :--- | :--- |
| `-wizard` | - | `false` | Ejecuta el asistente interactivo en terminal |
| `-duck-domain` | `DUCKDNS_DOMAIN` | `""` | Subdominio de DuckDNS (ej. `mi-nodo`) |
| `-duck-token` | `DUCKDNS_TOKEN` | `""` | Token API privado de DuckDNS |
| `-upnp` | `ENABLE_UPNP` | `true` | Activar auto-apertura UPnP y diagnóstico de NAT |
| `-no-upnp` | - | `false` | Desactivar completamente UPnP |
| `-port` | `PORT` | `9000` | Puerto HTTP y WebSocket (Señalización PeerJS y Dashboard) |
| `-turn-port` | `TURN_PORT` | `3478` | Puerto UDP de escucha para el servidor TURN/STUN |
| `-public-ip` | `PUBLIC_IP` | *(Auto-detectada)* | IP pública o dominio manual accesible desde el exterior |
| `-user` | - | `pingo` | Nombre de usuario por defecto para TURN |
| `-password` | - | `pingosecret` | Contraseña por defecto para TURN |
| `-secret` | `TURN_STATIC_AUTH_SECRET` | `pingo-static-auth-secret` | Secreto estático para autenticación HMAC |
| `-realm` | - | `pingo` | Realm de autenticación TURN |
| `-min-port` | - | `49152` | Puerto UDP inicial para relay WebRTC |
| `-max-port` | - | `65535` | Puerto UDP final para relay WebRTC |
| `-tls` | - | `false` | Activar HTTPS/WSS directo |
| `-tls-cert` | - | `cert.pem` | Ruta al certificado TLS |
| `-tls-key` | - | `key.pem` | Ruta a la clave privada TLS |
| `-app-url` | - | `https://pingo.accreativos.com` | URL base de Pingo para generar los enlaces QR |

---

## 🔍 Diagnóstico de Red: UPnP vs. CGNAT

El servidor clasifica automáticamente la red en uno de 3 estados:

1. 🟢 **UPnP Activo + Sin CGNAT**: 
   * **Diagnóstico**: Tu router soporta UPnP y tu proveedor de internet te asigna IPv4 pública directa.
   * **Acción**: Nada. Todo funciona de forma 100% automática sin tocar tu router.
2. 🟡 **UPnP Activo + CGNAT Detectado**: 
   * **Diagnóstico**: El router abre los puertos en tu red local, pero tu operadora (ej. Digi, MásMóvil, Pepephone sin salir de CGNAT) bloquea las conexiones entrantes desde internet.
   * **Acción**: Puedes llamar a tu operadora para salir de CGNAT (en Digi "Conexión Plus", en O2/Movistar ya viene desactivado), o usar **Cloudflare Tunnel** / **Tailscale Funnel**.
3. 🔴 **UPnP No Detectado**: 
   * **Diagnóstico**: UPnP está desactivado en el router o hay un firewall bloqueándolo.
   * **Acción**: Activa UPnP en la configuración de tu router (`192.168.1.1`) o realiza apertura manual de los puertos `9000/TCP` y `3478/UDP`.
