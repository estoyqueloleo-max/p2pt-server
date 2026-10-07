package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/acme"
)

// ObtainOrRenewCloudHubCert solicita o renueva un certificado oficial Let's Encrypt para el subdominio
// del appliance (<id>.appliances.klitosan.com) delegando el reto DNS-01 en el Cloud Hub.
func ObtainOrRenewCloudHubCert(cfg *Config) (tls.Certificate, error) {
	applianceID := strings.TrimSpace(cfg.DDNSApplianceID)
	token := strings.TrimSpace(cfg.DDNSSecretToken)
	hubEndpoint := strings.TrimSpace(cfg.DDNSHubEndpoint)

	if applianceID == "" || token == "" {
		return tls.Certificate{}, fmt.Errorf("DDNS_APPLIANCE_ID o DDNS_SECRET_TOKEN no configurados")
	}

	if hubEndpoint == "" {
		hubEndpoint = "https://web.appliance.klitosan.com"
	}
	hubEndpoint = strings.TrimRight(hubEndpoint, "/")

	// Determinar el FQDN del appliance (ej: pingo.appliances.klitosan.com)
	fullDomain := fmt.Sprintf("%s.appliances.klitosan.com", applianceID)

	certPath, keyPath := getPersistentCertPaths(cfg)

	// 1. Reutilizar certificado en caché si es válido (mínimo 30 días restantes)
	if cert, ok := CheckExistingCertValid(certPath, keyPath, fullDomain, 30); ok {
		return cert, nil
	}

	log.Printf("[ACME-CloudHub] 🔐 Iniciando solicitud de certificado Let's Encrypt para %s vía DNS-01 delegado en Hub...", fullDomain)

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	accountKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("error generando clave de cuenta ACME: %w", err)
	}

	client := &acme.Client{
		Key:          accountKey,
		DirectoryURL: acme.LetsEncryptURL,
	}

	acct := &acme.Account{}
	_, err = client.Register(ctx, acct, acme.AcceptTOS)
	if err != nil && !strings.Contains(strings.ToLower(err.Error()), "already") {
		log.Printf("[ACME-CloudHub] Registro de cuenta ACME: %v", err)
	}

	order, err := client.AuthorizeOrder(ctx, []acme.AuthzID{{Type: "dns", Value: fullDomain}})
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("error en AuthorizeOrder ACME: %w", err)
	}

	for _, authzURL := range order.AuthzURLs {
		authz, err := client.GetAuthorization(ctx, authzURL)
		if err != nil {
			return tls.Certificate{}, fmt.Errorf("error obteniendo autorización ACME: %w", err)
		}
		if authz.Status == acme.StatusValid {
			continue
		}

		var dnsChal *acme.Challenge
		for _, chal := range authz.Challenges {
			if chal.Type == "dns-01" {
				dnsChal = chal
				break
			}
		}

		if dnsChal == nil {
			return tls.Certificate{}, fmt.Errorf("no se encontró reto dns-01 para %s", fullDomain)
		}

		txtVal, err := client.DNS01ChallengeRecord(dnsChal.Token)
		if err != nil {
			return tls.Certificate{}, fmt.Errorf("error calculando valor TXT DNS-01: %w", err)
		}

		// Publicar registro TXT en Cloudflare a través del Cloud Hub
		log.Printf("[ACME-CloudHub] Publicando reto DNS-01 en Cloud Hub (%s)...", hubEndpoint)
		if err := setCloudHubTXTChallenge(ctx, hubEndpoint, applianceID, token, txtVal); err != nil {
			return tls.Certificate{}, fmt.Errorf("fallo al publicar TXT en Cloud Hub: %w", err)
		}

		// Esperar 15s para propagación DNS en Cloudflare Edge
		log.Println("[ACME-CloudHub] Esperando 15s para propagación DNS en Cloudflare...")
		select {
		case <-time.After(15 * time.Second):
		case <-ctx.Done():
			_ = clearCloudHubTXTChallenge(context.Background(), hubEndpoint, applianceID, token)
			return tls.Certificate{}, ctx.Err()
		}

		// Notificar a Let's Encrypt para validar el reto
		log.Println("[ACME-CloudHub] Notificando a Let's Encrypt para verificar reto DNS-01...")
		if _, err := client.Accept(ctx, dnsChal); err != nil {
			_ = clearCloudHubTXTChallenge(context.Background(), hubEndpoint, applianceID, token)
			return tls.Certificate{}, fmt.Errorf("error aceptando reto ACME: %w", err)
		}

		if _, err := client.WaitAuthorization(ctx, authz.URI); err != nil {
			_ = clearCloudHubTXTChallenge(context.Background(), hubEndpoint, applianceID, token)
			return tls.Certificate{}, fmt.Errorf("fallo en autorización Let's Encrypt: %w", err)
		}
	}

	// Limpiar registro TXT temporal en Cloudflare a través del Hub
	_ = clearCloudHubTXTChallenge(context.Background(), hubEndpoint, applianceID, token)

	order, err = client.WaitOrder(ctx, order.URI)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("error esperando orden ACME: %w", err)
	}

	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("error generando clave de certificado: %w", err)
	}

	csrTemplate := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: fullDomain},
		DNSNames: []string{fullDomain},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, certKey)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("error creando CSR: %w", err)
	}

	derChain, _, err := client.CreateOrderCert(ctx, order.FinalizeURL, csrDER, true)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("error emitiendo certificado en Let's Encrypt: %w", err)
	}

	var certPEM []byte
	for _, der := range derChain {
		certPEM = append(certPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}

	keyBytes, err := x509.MarshalECPrivateKey(certKey)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("error codificando clave privada: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})

	if dir := filepath.Dir(certPath); dir != "" && dir != "." {
		_ = os.MkdirAll(dir, 0755)
	}
	_ = os.WriteFile(certPath, certPEM, 0600)
	_ = os.WriteFile(keyPath, keyPEM, 0600)

	cfg.TLSCertFile = certPath
	cfg.TLSKeyFile = keyPath

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("error cargando certificado recién emitido: %w", err)
	}

	log.Printf("[ACME-CloudHub] 🎉 Certificado oficial Let's Encrypt emitido e instalado con éxito para %s!", fullDomain)
	return tlsCert, nil
}

func setCloudHubTXTChallenge(ctx context.Context, hubEndpoint, applianceID, token, txtValue string) error {
	url := fmt.Sprintf("%s/api/v1/ddns/acme-challenge", hubEndpoint)
	payload, _ := json.Marshal(map[string]string{"value": txtValue})

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("X-Appliance-ID", applianceID)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("el Cloud Hub respondió HTTP %d", resp.StatusCode)
	}
	return nil
}

func clearCloudHubTXTChallenge(ctx context.Context, hubEndpoint, applianceID, token string) error {
	url := fmt.Sprintf("%s/api/v1/ddns/acme-challenge", hubEndpoint)
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-Appliance-ID", applianceID)
	req.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}
