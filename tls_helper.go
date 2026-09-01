package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// EnsureTLSCertificates busca o genera automáticamente certificados TLS con soporte para IPs locales, nip.io y mDNS
func EnsureTLSCertificates(cfg *Config) (tls.Certificate, error) {
	certPaths := []string{
		cfg.TLSCertFile,
		"/media/mmcblk0p1/cert.pem",
		"/boot/cert.pem",
		"./cert.pem",
	}
	keyPaths := []string{
		cfg.TLSKeyFile,
		"/media/mmcblk0p1/key.pem",
		"/boot/key.pem",
		"./key.pem",
	}

	for i := range certPaths {
		cPath := certPaths[i]
		kPath := keyPaths[i]
		if cPath != "" && kPath != "" {
			if _, errC := os.Stat(cPath); errC == nil {
				if _, errK := os.Stat(kPath); errK == nil {
					cert, err := tls.LoadX509KeyPair(cPath, kPath)
					if err == nil {
						log.Printf("[TLS] Certificados existentes cargados desde %s y %s", cPath, kPath)
						cfg.TLSCertFile = cPath
						cfg.TLSKeyFile = kPath
						return cert, nil
					}
				}
			}
		}
	}

	log.Println("[TLS] Generando nuevo certificado SSL/TLS con SANs (nip.io, mDNS, IPs locales)...")
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("error generando clave privada: %w", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("error generando número de serie: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Pingo Appliance Node"},
			CommonName:   "pingo.local",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	dnsNames := map[string]bool{
		"localhost":   true,
		"pingo.local": true,
	}
	ipList := []net.IP{
		net.ParseIP("127.0.0.1"),
		net.ParseIP("::1"),
	}

	if ifaces, err := net.Interfaces(); err == nil {
		for _, iface := range ifaces {
			if addrs, err := iface.Addrs(); err == nil {
				for _, addr := range addrs {
					var ip net.IP
					switch v := addr.(type) {
					case *net.IPNet:
						ip = v.IP
					case *net.IPAddr:
						ip = v.IP
					}
					if ip != nil && !ip.IsLoopback() {
						ipList = append(ipList, ip)
						ipStr := ip.String()
						dnsNames[fmt.Sprintf("%s.nip.io", ipStr)] = true
					}
				}
			}
		}
	}

	if cfg.DuckDomain != "" {
		fullDuck := formatFullDomain(cfg.DuckDomain)
		dnsNames[fullDuck] = true
	}

	for dns := range dnsNames {
		template.DNSNames = append(template.DNSNames, dns)
	}
	template.IPAddresses = ipList

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("error creando certificado: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	privBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("error codificando clave: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes})

	saveDirs := []string{"/media/mmcblk0p1", "/boot", "/tmp"}
	for _, dir := range saveDirs {
		if fi, err := os.Stat(dir); err == nil && fi.IsDir() {
			cFile := filepath.Join(dir, "cert.pem")
			kFile := filepath.Join(dir, "key.pem")
			_ = os.WriteFile(cFile, certPEM, 0644)
			_ = os.WriteFile(kFile, keyPEM, 0600)
			cfg.TLSCertFile = cFile
			cfg.TLSKeyFile = kFile
			break
		}
	}

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("error cargando clave en memoria: %w", err)
	}

	log.Printf("[TLS] Certificado SSL/TLS preparado para dominios: %s", strings.Join(template.DNSNames, ", "))
	return cert, nil
}
