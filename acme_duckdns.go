package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/acme"
)

// CheckExistingCertValid inspects a cert file on disk and returns true if it exists,
// matches the target domain, and has at least minDays remaining before expiration.
func CheckExistingCertValid(certPath, keyPath, domain string, minDays int) (tls.Certificate, bool) {
	if certPath == "" || keyPath == "" {
		return tls.Certificate{}, false
	}
	if _, err := os.Stat(certPath); err != nil {
		return tls.Certificate{}, false
	}
	if _, err := os.Stat(keyPath); err != nil {
		return tls.Certificate{}, false
	}

	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil || len(cert.Certificate) == 0 {
		return tls.Certificate{}, false
	}

	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return tls.Certificate{}, false
	}

	matches := false
	cleanTarget := strings.ToLower(strings.TrimSpace(domain))
	for _, dns := range x509Cert.DNSNames {
		if strings.EqualFold(dns, cleanTarget) {
			matches = true
			break
		}
	}
	if !matches && strings.EqualFold(x509Cert.Subject.CommonName, cleanTarget) {
		matches = true
	}

	if !matches {
		return tls.Certificate{}, false
	}

	remaining := time.Until(x509Cert.NotAfter)
	if remaining < time.Duration(minDays)*24*time.Hour {
		log.Printf("[ACME] Certificado existente para %s próximo a expirar (quedan %v). Requiere renovación.", cleanTarget, remaining.Round(time.Hour))
		return tls.Certificate{}, false
	}

	log.Printf("[ACME] Certificado oficial Let's Encrypt cargado para %s (válido por %v más)", cleanTarget, remaining.Round(24*time.Hour))
	return cert, true
}

// ObtainOrRenewDuckDNSCert uses the ACME DNS-01 challenge with DuckDNS API to obtain
// a free, trusted Let's Encrypt SSL certificate for <subdomain>.duckdns.org without needing open ports.
func ObtainOrRenewDuckDNSCert(cfg *Config) (tls.Certificate, error) {
	domain := cleanDuckDomain(cfg.DuckDomain)
	token := strings.TrimSpace(cfg.DuckToken)
	if domain == "" || token == "" {
		return tls.Certificate{}, fmt.Errorf("duckdns domain o token no configurados")
	}

	fullDomain := formatFullDomain(domain)

	// Determine persistent paths for storing certificates
	certPath, keyPath := getPersistentCertPaths(cfg)

	// 1. Check if valid cached certificate is already available (at least 30 days remaining)
	if cert, ok := CheckExistingCertValid(certPath, keyPath, fullDomain, 30); ok {
		return cert, nil
	}

	log.Printf("[ACME] Iniciando solicitud de certificado Let's Encrypt para %s vía DNS-01 (DuckDNS)...", fullDomain)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	accountKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("error generando clave de cuenta ACME: %w", err)
	}

	client := &acme.Client{
		Key:          accountKey,
		DirectoryURL: acme.LetsEncryptURL,
	}

	// Register account (accept TOS)
	acct := &acme.Account{}
	_, err = client.Register(ctx, acct, acme.AcceptTOS)
	if err != nil && !strings.Contains(strings.ToLower(err.Error()), "already") {
		// Non-fatal if already registered
		log.Printf("[ACME] Registro de cuenta ACME: %v", err)
	}

	// Request order for the DuckDNS domain
	order, err := client.AuthorizeOrder(ctx, []acme.AuthzID{{Type: "dns", Value: fullDomain}})
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("error en AuthorizeOrder ACME: %w", err)
	}

	// Process DNS-01 challenge for each authorization URL
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

		// Publish TXT record on DuckDNS
		log.Printf("[ACME] Publicando registro TXT para validación DNS-01 en DuckDNS...")
		if err := SetDuckDNSTXTRecord(ctx, domain, token, txtVal); err != nil {
			return tls.Certificate{}, fmt.Errorf("fallo al publicar TXT en DuckDNS: %w", err)
		}

		// Wait 15 seconds for DNS propagation across DuckDNS nameservers
		log.Println("[ACME] Esperando 15s para propagación DNS en DuckDNS...")
		select {
		case <-time.After(15 * time.Second):
		case <-ctx.Done():
			_ = ClearDuckDNSTXTRecord(context.Background(), domain, token)
			return tls.Certificate{}, ctx.Err()
		}

		// Inform ACME server challenge is ready
		log.Println("[ACME] Notificando a Let's Encrypt para verificar reto DNS-01...")
		if _, err := client.Accept(ctx, dnsChal); err != nil {
			_ = ClearDuckDNSTXTRecord(context.Background(), domain, token)
			return tls.Certificate{}, fmt.Errorf("error aceptando reto ACME: %w", err)
		}

		// Wait for authorization to succeed
		if _, err := client.WaitAuthorization(ctx, authz.URI); err != nil {
			_ = ClearDuckDNSTXTRecord(context.Background(), domain, token)
			return tls.Certificate{}, fmt.Errorf("fallo en autorización Let's Encrypt: %w", err)
		}
	}

	// Clean up DuckDNS TXT record
	_ = ClearDuckDNSTXTRecord(context.Background(), domain, token)

	// Wait for order readiness
	order, err = client.WaitOrder(ctx, order.URI)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("error esperando orden ACME: %w", err)
	}

	// Generate certificate private key and CSR
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

	// Finalize order and retrieve certificate chain
	derChain, _, err := client.CreateOrderCert(ctx, order.FinalizeURL, csrDER, true)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("error emitiendo certificado en Let's Encrypt: %w", err)
	}

	// Encode certificate chain to PEM
	var certPEM []byte
	for _, der := range derChain {
		certPEM = append(certPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}

	// Encode private key to PEM
	keyBytes, err := x509.MarshalECPrivateKey(certKey)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("error codificando clave privada: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})

	// Save PEMs to disk
	if dir := filepath.Dir(certPath); dir != "" && dir != "." {
		_ = os.MkdirAll(dir, 0755)
	}
	if err := os.WriteFile(certPath, certPEM, 0600); err != nil {
		log.Printf("[ACME] Advertencia: no se pudo guardar cert.pem en %s: %v", certPath, err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		log.Printf("[ACME] Advertencia: no se pudo guardar key.pem en %s: %v", keyPath, err)
	}

	cfg.TLSCertFile = certPath
	cfg.TLSKeyFile = keyPath

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("error cargando clave y certificado recién emitidos: %w", err)
	}

	log.Printf("[ACME] 🎉 Certificado Let's Encrypt emitido e instalado con éxito para %s!", fullDomain)
	return tlsCert, nil
}

// getPersistentCertPaths returns preferred filepaths to save certificates
func getPersistentCertPaths(cfg *Config) (string, string) {
	if cfg.TLSCertFile != "" && cfg.TLSKeyFile != "" && cfg.TLSCertFile != "cert.pem" {
		return cfg.TLSCertFile, cfg.TLSKeyFile
	}

	candidates := []string{
		"/media/mmcblk0p1",
		"/boot",
		"/etc/ssl/pingo",
		".",
	}

	for _, dir := range candidates {
		if fi, err := os.Stat(dir); err == nil && fi.IsDir() {
			testFile := filepath.Join(dir, ".pingo_write_test")
			if errW := os.WriteFile(testFile, []byte("ok"), 0644); errW == nil {
				_ = os.Remove(testFile)
				return filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
			}
		}
	}

	return "./cert.pem", "./key.pem"
}
