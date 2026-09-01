package main

import (
	"crypto/tls"
	"log"
	"net/http"
	"os/exec"
	"time"
)

// SyncSystemClock intenta sincronizar el reloj del sistema mediante HTTP Date header y ntpd
func SyncSystemClock() bool {
	endpoints := []string{
		"http://www.google.com",
		"http://www.cloudflare.com",
		"http://duckdns.org",
	}

	client := &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	for _, ep := range endpoints {
		req, err := http.NewRequest("HEAD", ep, nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		dateHdr := resp.Header.Get("Date")
		if dateHdr != "" {
			if parsedTime, err := http.ParseTime(dateHdr); err == nil {
				formatted := parsedTime.UTC().Format("2006-01-02 15:04:05")
				log.Printf("[TimeSync] 🕒 Fecha/Hora remota detectada: %s (Hora local anterior: %v)", formatted, time.Now().UTC())
				_ = exec.Command("date", "-u", "-s", formatted).Run()

				// Lanzar ntpd en segundo plano si está disponible
				go func() {
					_ = exec.Command("ntpd", "-d", "-n", "-q", "-p", "pool.ntp.org").Run()
				}()
				return true
			}
		}
	}

	return false
}
