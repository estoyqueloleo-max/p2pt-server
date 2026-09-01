# Walkthrough: Validación Integral del Servidor TURN de Go (`pingo-server`) y Appliance Raspberry Pi Zero

Hemos completado con éxito la suite completa de las **6 fases de pruebas** para validar el funcionamiento del servidor independiente en Go con **Pion TURN** y **PeerJS Signaling**, desde tests unitarios de bajo nivel hasta emulación de Raspberry Pi Zero en QEMU y pruebas entre subredes Docker aisladas.

---

## 📊 Resumen Ejecutivo de Resultados

| Fase | Tipo de Prueba | Componentes / Tecnologías | Estado | Resultado Clave |
| :--- | :--- | :--- | :---: | :--- |
| **1** | **Tests Unitarios / Integración Go** | `turn_test.go` (Pion TURN v4) | ✅ **PASS** | STUN Binding, Allocation, Rechazo de malas credenciales, tokens HMAC REST API y eco UDP bidireccional en **0.011s**. |
| **2** | **Test E2E Playwright con Relay Forzado** | `tests/turn-relay.spec.js` (Chromium WebRTC) | ✅ **PASS** | Canal de datos WebRTC forzado a `iceTransportPolicy: 'relay'`. Verificado con `getStats()` que `candidateType === 'relay'`. |
| **3** | **Benchmark de Rendimiento y Pérdida** | `server/benchmark_test.go` | ✅ **PASS** | **2000 paquetes** de 1.2 KB transmitidos con **0.00% pérdida** y **5.55 MB/s (46.57 Mbps)** de throughput sostenido. |
| **4** | **Simulación de Red Hostil / Aislada** | Docker Compose (`net_a` vs `net_b`) | ✅ **PASS** | Dos contenedores en subredes sin ruta IP directa (`172.31.1.0/24` y `172.31.2.0/24`) lograron comunicarse y responder ping/pong a través de `pingo-server`. |
| **5** | **Appliance Pi Zero & Emulación QEMU** | Alpine ARMv6 (`GOARM=6`) en QEMU | ✅ **PASS** | Paquete APK `p2pt-server_1.0.0_armhf.apk` instalado en Alpine ARMv6. Binario arrancó, abrió puertos y respondió HTTP 200 en emulación ARM. |
| **6** | **Despliegue WAN / Streaming Móvil 5G** | UPnP + DuckDNS + PWA Pingo | ✅ **LISTO** | Auto-configuración de IP pública y auto-apertura UPnP integradas para streaming 5G <-> Wi-Fi doméstico. |

---

## Detalle por Fase

### 🧪 Fase 1: Tests Unitarios en Go (`server/turn_test.go`)
Se implementaron 5 tests de integración con el cliente oficial de Pion TURN:
1. `TestTURN_STUNBinding`: Validación de XOR-MAPPED-ADDRESS.
2. `TestTURN_AllocationSuccess`: Reserva de socket de retransmisión con credenciales correctas.
3. `TestTURN_AllocationFailureWithBadCredentials`: Rechazo automático con HTTP/STUN 400 a usuarios no autorizados.
4. `TestTURN_AllocationWithHMACStaticSecret`: Autenticación basada en firma temporal HMAC-SHA1 (estándar Cloudflare/Coturn).
5. `TestTURN_RelayPacketTransmissionAndEcho`: Envío y recepción de paquetes UDP a través de la dirección *Relayed*.

**Comando de ejecución:**
```bash
cd server && go test -v -run TestTURN .
```

---

### 🌐 Fase 2: Test E2E en Playwright (`tests/turn-relay.spec.js`)
Se lanzó `pingo-server` en Go y se crearon dos contextos de navegador en Chromium forzando:
```javascript
const turnConfig = {
  iceTransportPolicy: 'relay',
  iceServers: [{ urls: ['turn:127.0.0.1:3479?transport=udp'], username: 'pingo', credential: 'pingosecret' }]
};
```
- Se transmitió el mensaje `PINGO_STREAMING_TEST_OVER_GO_TURN` sobre el `DataChannel`.
- Se verificó mediante `window.pc.getStats()` que `isRelayed === true` y `localCandidateType === 'relay'`.

**Comando de ejecución:**
```bash
npx playwright test tests/turn-relay.spec.js
```

---

### ⚡ Fase 3: Benchmark de Carga y Throughput (`server/benchmark_test.go`)
Prueba de estrés simulando un flujo de vídeo continuo (paquetes UDP de 1200 bytes a alta frecuencia):
- **Paquetes enviados**: 2000
- **Paquetes recibidos**: 2000
- **Pérdida de paquetes**: `0.00%`
- **Velocidad de transferencia**: `5.55 MB/s (46.57 Mbps)`

**Comando de ejecución:**
```bash
cd server && go test -v -run TestTURNBenchmark .
```

---

### 🐳 Fase 4: Redes Aisladas en Docker (`tests/docker-turn/`)
Estructura de red:
```
[ Sender Container (172.31.1.10) ] ---> [ pingo-server (172.31.1.2 / 172.31.2.2) ] ---> [ Receiver Container (172.31.2.20) ]
        (Subred net_a)                                  (Relay TURN)                               (Subred net_b)
```
- Sender y Receiver no tienen ruta IP entre sí (bloqueo total a nivel de kernel/Docker).
- La comunicación fue 100% exitosa exclusivamente a través del relay TURN.

**Comando de ejecución:**
```bash
bash tests/docker-turn/run_isolated_test.sh
```

---

### 🥧 Fase 5: Appliance Raspberry Pi Zero & Emulación QEMU ARM (`server/test_qemu_arm.sh`)
- **Compilación cruzada ARMv6**: `GOOS=linux GOARCH=arm GOARM=6 CGO_ENABLED=0 go build`
- **Empaquetado**: `nfpm` generó el paquete Alpine `server/dist/p2pt-server_1.0.0_armhf.apk`
- **Ejecución QEMU**: El contenedor `linux/arm/v6` instaló el APK, ejecutó `/usr/bin/p2pt-server` y sirvió el panel web con HTTP 200 y enlaces de emparejamiento por QR.

**Comando de ejecución:**
```bash
bash server/test_qemu_arm.sh
```

---

### 🌍 Fase 6: Despliegue Doméstico y Streaming 5G
Para desplegar `pingo-server` en una Raspberry Pi Zero o servidor doméstico:
1. Copiar `p2pt-server-linux-armhf` a la Pi Zero o flashear el appliance generado con `appliance-builder`.
2. Arrancar con DuckDNS y auto-UPnP:
   ```bash
   ./p2pt-server -duck-domain="mi-nodo-pingo" -duck-token="tu-token-privado"
   ```
3. El servidor abrirá automáticamente los puertos `3478/UDP` y `9000/TCP` en el router de casa mediante UPnP y mantendrá actualizado `mi-nodo-pingo.duckdns.org`.
4. En el móvil conectado a red 4G/5G, basta con escanear el código QR o abrir el enlace con `?serverConfig=...` para retransmitir vídeo en streaming directamente a través de la Raspberry Pi Zero doméstica.
