package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// RunCLIWizard presents an interactive CLI questionnaire for the user
func RunCLIWizard(cfg *Config) {
	reader := bufio.NewReader(os.Stdin)

	fmt.Println("==================================================================")
	fmt.Println("       🧙 ASISTENTE DE CONFIGURACIÓN PASO A PASO (PINGO)          ")
	fmt.Println("==================================================================")
	fmt.Println(" Este asistente te ayudará a configurar tu nodo doméstico en 1 min.")
	fmt.Println(" Si pulsas [ENTER] sin escribir nada, se usarán los valores por defecto.")
	fmt.Println("------------------------------------------------------------------")

	// 1. DuckDNS Subdomain
	fmt.Print("\n🔹 Paso 1: Subdominio DuckDNS (ej. 'mi-nodo', o ENTER para usar IP directa): ")
	domainInput, _ := reader.ReadString('\n')
	domainInput = strings.TrimSpace(domainInput)

	if domainInput != "" {
		fmt.Print("🔹 Paso 2: Token privado de DuckDNS: ")
		tokenInput, _ := reader.ReadString('\n')
		tokenInput = strings.TrimSpace(tokenInput)

		if tokenInput != "" {
			fmt.Println("⏳ Probando credenciales de DuckDNS...")
			mgr := NewDuckDNSManager(domainInput, tokenInput, nil)
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			ok, msg, _ := mgr.Update(ctx, "")
			cancel()

			if ok {
				fmt.Printf("✅ ¡Conectado con éxito! Tu dominio es: %s\n", formatFullDomain(domainInput))
				cfg.DuckDomain = domainInput
				cfg.DuckToken = tokenInput
				cfg.PublicIP = formatFullDomain(domainInput)
			} else {
				fmt.Printf("⚠️ Advertencia: %s. Se guardará de todos modos.\n", msg)
				cfg.DuckDomain = domainInput
				cfg.DuckToken = tokenInput
				cfg.PublicIP = formatFullDomain(domainInput)
			}
		}
	}

	// 2. Red Comunitaria / Topic P2P
	fmt.Printf("\n🔹 Paso 3: Red Comunitaria / Topic P2P (ej. 'amigos-valencia', o ENTER para '%s'): ", cfg.TopicID)
	topicInput, _ := reader.ReadString('\n')
	topicInput = strings.TrimSpace(topicInput)
	if topicInput != "" {
		cfg.TopicID = topicInput
		fmt.Printf("✅ Red comunitaria configurada como: '%s' (InfoHash: %s)\n", cfg.TopicID, DeriveInfoHash(cfg.TopicID))
	} else {
		fmt.Printf("ℹ️ Usando red por defecto: '%s'\n", cfg.TopicID)
	}

	// 3. HTTP Port
	fmt.Printf("\n🔹 Paso 4: Puerto HTTP y WebSocket [%d]: ", cfg.HTTPPort)
	portInput, _ := reader.ReadString('\n')
	portInput = strings.TrimSpace(portInput)
	if portInput != "" {
		if p, err := strconv.Atoi(portInput); err == nil && p > 0 {
			cfg.HTTPPort = p
		}
	}

	// 3. TURN Port
	fmt.Printf("🔹 Paso 4: Puerto TURN UDP [%d]: ", cfg.TURNPort)
	turnInput, _ := reader.ReadString('\n')
	turnInput = strings.TrimSpace(turnInput)
	if turnInput != "" {
		if p, err := strconv.Atoi(turnInput); err == nil && p > 0 {
			cfg.TURNPort = p
		}
	}

	// 4. UPnP Mapping
	fmt.Print("🔹 Paso 5: ¿Intentar abrir puertos en el router vía UPnP automáticamente? (S/n): ")
	upnpInput, _ := reader.ReadString('\n')
	upnpInput = strings.TrimSpace(strings.ToLower(upnpInput))
	if upnpInput == "n" || upnpInput == "no" {
		cfg.EnableUPnP = false
		fmt.Println("ℹ️ UPnP desactivado por el usuario.")
	} else {
		cfg.EnableUPnP = true
		fmt.Println("✅ UPnP habilitado para auto-configuración del router.")
	}

	fmt.Println("\n==================================================================")
	fmt.Println("        🎉 ¡CONFIGURACIÓN COMPLETADA CON ÉXITO!                   ")
	fmt.Println("==================================================================")
}
