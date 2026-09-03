package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"
)

const CurrentVersion = "1.1.0"

type GithubAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
	Size               int64  `json:"size"`
}

type GithubRelease struct {
	TagName     string        `json:"tag_name"`
	Name        string        `json:"name"`
	Description string        `json:"body"`
	Assets      []GithubAsset `json:"assets"`
	PublishedAt time.Time     `json:"published_at"`
}

type UpdaterManager struct {
	RepoOwner       string
	RepoName        string
	CurrentVersion  string
	CheckInterval   time.Duration
	stopChan        chan struct{}
}

func NewUpdaterManager(repoOwner, repoName string) *UpdaterManager {
	if repoOwner == "" {
		repoOwner = "estoyqueloleo-max"
	}
	if repoName == "" {
		repoName = "p2pt-server"
	}
	return &UpdaterManager{
		RepoOwner:      repoOwner,
		RepoName:       repoName,
		CurrentVersion: CurrentVersion,
		CheckInterval:  12 * time.Hour,
		stopChan:       make(chan struct{}),
	}
}

// FetchLatestRelease checks GitHub for the newest release
func (u *UpdaterManager) FetchLatestRelease() (*GithubRelease, error) {
	apiURL := fmt.Sprintf("https://api.github.com/repos/%s/%s/releases/latest", u.RepoOwner, u.RepoName)
	client := &http.Client{Timeout: 10 * time.Second}

	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Pingo-Server-Updater/"+u.CurrentVersion)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("github api returned status: %d", resp.StatusCode)
	}

	var release GithubRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return nil, err
	}
	return &release, nil
}

// IsNewerVersion returns true if latest is strictly higher than current
func IsNewerVersion(current, latest string) bool {
	cleanCur := strings.TrimPrefix(strings.TrimSpace(current), "v")
	cleanLat := strings.TrimPrefix(strings.TrimSpace(latest), "v")
	return cleanLat != "" && cleanLat != cleanCur && cleanLat > cleanCur
}

// GetBinaryAssetName returns the expected asset name for the current architecture
func GetBinaryAssetName() string {
	osName := runtime.GOOS
	arch := runtime.GOARCH

	if osName == "linux" && arch == "arm" {
		return "p2pt-server-linux-armhf"
	}
	if osName == "windows" {
		return fmt.Sprintf("p2pt-server-%s-%s.exe", osName, arch)
	}
	return fmt.Sprintf("p2pt-server-%s-%s", osName, arch)
}

// DownloadAndApplyUpdate downloads the binary and atomically replaces the running executable
func (u *UpdaterManager) DownloadAndApplyUpdate(assetURL string) error {
	execPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}

	log.Printf("[Updater] Descargando actualización desde: %s...", assetURL)
	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Get(assetURL)
	if err != nil {
		return fmt.Errorf("failed to download update: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to download: HTTP %d", resp.StatusCode)
	}

	tempFile := execPath + ".new"
	out, err := os.OpenFile(tempFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}

	hasher := sha256.New()
	multiWriter := io.MultiWriter(out, hasher)

	written, err := io.Copy(multiWriter, resp.Body)
	out.Close()
	if err != nil {
		os.Remove(tempFile)
		return fmt.Errorf("error writing update file: %w", err)
	}

	checksum := hex.EncodeToString(hasher.Sum(nil))
	log.Printf("[Updater] Descarga completada (%d bytes). SHA256: %s", written, checksum)

	// Atomic replacement
	if err := os.Rename(tempFile, execPath); err != nil {
		os.Remove(tempFile)
		return fmt.Errorf("failed to replace executable: %w", err)
	}

	log.Println("✅ [Updater] Binario actualizado con éxito. El nuevo binario se ejecutará en el próximo reinicio.")
	return nil
}

// StartBackgroundCheck initiates periodic update checks
func (u *UpdaterManager) StartBackgroundCheck() {
	go func() {
		ticker := time.NewTicker(u.CheckInterval)
		defer ticker.Stop()

		// Initial check after 30 seconds
		time.Sleep(30 * time.Second)
		u.checkOnce()

		for {
			select {
			case <-ticker.C:
				u.checkOnce()
			case <-u.stopChan:
				return
			}
		}
	}()
}

func (u *UpdaterManager) checkOnce() {
	release, err := u.FetchLatestRelease()
	if err != nil {
		log.Printf("[Updater] Error al comprobar actualizaciones: %v", err)
		return
	}

	if IsNewerVersion(u.CurrentVersion, release.TagName) {
		log.Printf("📢 [Updater] Nueva versión encontrada: %s (Actual: %s)", release.TagName, u.CurrentVersion)
		expectedAsset := GetBinaryAssetName()

		for _, asset := range release.Assets {
			if asset.Name == expectedAsset {
				log.Printf("[Updater] Descargando release '%s' (%s)...", release.TagName, asset.Name)
				if err := u.DownloadAndApplyUpdate(asset.BrowserDownloadURL); err != nil {
					log.Printf("❌ [Updater] Error aplicando actualización: %v", err)
				}
				return
			}
		}
	} else {
		log.Printf("[Updater] El servidor está al día (Versión %s)", u.CurrentVersion)
	}
}

// Stop stops the updater
func (u *UpdaterManager) Stop() {
	close(u.stopChan)
}
