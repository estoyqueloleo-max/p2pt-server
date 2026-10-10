package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	webpush "github.com/SherClockHolmes/webpush-go"
)

const (
	defaultVAPIDPublicKey  = "BEJ45uzzL_hw2MpJaxTw8Jwk-hbqJE3D5GI7TWMBaYOLkKoVsJQJGVZrpDOASMBpsCpF3bFI2LFZaZecqAWfAKk"
	defaultVAPIDPrivateKey = "uwHBVq5KHmevNRtVBTP62G_n6mFeH7vOQsVlpG_YHWU"
	defaultSubscriberEmail = "admin@accreativos.com"
)

// PushSubscriptionRecord holds stored subscription data and user salt
type PushSubscriptionRecord struct {
	UserPublicKey string                `json:"userPublicKey"`
	Salt          string                `json:"salt"`
	Endpoint      string                `json:"endpoint"`
	Keys          webpush.Keys          `json:"keys"`
	LastSeen      time.Time             `json:"last_seen"`
	Subscription  *webpush.Subscription `json:"subscription"`
}

// PushManager handles web push subscriptions and notification delivery
type PushManager struct {
	mu              sync.RWMutex
	storePath       string
	records         map[string]*PushSubscriptionRecord
	vapidPublicKey  string
	vapidPrivateKey string
	subscriberEmail string
}

func NewPushManager(dataDir string) *PushManager {
	if dataDir == "" {
		dataDir = "/var/lib/p2pt"
	}
	_ = os.MkdirAll(dataDir, 0755)

	pm := &PushManager{
		storePath:       filepath.Join(dataDir, "push_subscriptions.json"),
		records:         make(map[string]*PushSubscriptionRecord),
		vapidPublicKey:  os.Getenv("VAPID_PUBLIC_KEY"),
		vapidPrivateKey: os.Getenv("VAPID_PRIVATE_KEY"),
		subscriberEmail: os.Getenv("VAPID_SUBSCRIBER_EMAIL"),
	}

	if pm.vapidPublicKey == "" {
		pm.vapidPublicKey = defaultVAPIDPublicKey
	}
	if pm.vapidPrivateKey == "" {
		pm.vapidPrivateKey = defaultVAPIDPrivateKey
	}
	if pm.subscriberEmail == "" {
		pm.subscriberEmail = defaultSubscriberEmail
	}

	pm.loadFromDisk()
	return pm
}

func (pm *PushManager) loadFromDisk() {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	data, err := os.ReadFile(pm.storePath)
	if err != nil {
		return
	}

	var loaded map[string]*PushSubscriptionRecord
	if err := json.Unmarshal(data, &loaded); err == nil && loaded != nil {
		pm.records = loaded
		log.Printf("[PushManager] Cargadas %d suscripciones WebPush desde %s", len(pm.records), pm.storePath)
	}
}

func (pm *PushManager) saveToDiskLocked() {
	data, err := json.MarshalIndent(pm.records, "", "  ")
	if err != nil {
		log.Printf("[PushManager] Error serializando suscripciones: %v", err)
		return
	}
	tmpFile := pm.storePath + ".tmp"
	if err := os.WriteFile(tmpFile, data, 0600); err == nil {
		_ = os.Rename(tmpFile, pm.storePath)
	}
}

func generatePingoAuthToken(salt string) string {
	if salt == "" {
		return "public"
	}
	now := time.Now().UTC()
	timeKey := fmt.Sprintf("%d-%d-%d-%d", now.Year(), int(now.Month())-1, now.Day(), now.Hour())
	message := salt + timeKey
	hash := sha256.Sum256([]byte(message))
	return fmt.Sprintf("%x", hash)
}

// HandleSubscribe handles POST /push/subscribe
func (pm *PushManager) HandleSubscribe(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "*")
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var body struct {
		UserPublicKey  string          `json:"userPublicKey"`
		Salt           string          `json:"salt"`
		Endpoint       string          `json:"endpoint"`
		ExpirationTime *int64          `json:"expirationTime"`
		Keys           webpush.Keys    `json:"keys"`
	}

	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "Invalid Payload", http.StatusBadRequest)
		return
	}

	if body.UserPublicKey == "" || body.Endpoint == "" {
		http.Error(w, "UserPublicKey and Endpoint required", http.StatusBadRequest)
		return
	}

	pm.mu.Lock()
	defer pm.mu.Unlock()

	rec := &PushSubscriptionRecord{
		UserPublicKey: body.UserPublicKey,
		Salt:          body.Salt,
		Endpoint:      body.Endpoint,
		Keys:          body.Keys,
		LastSeen:      time.Now(),
		Subscription: &webpush.Subscription{
			Endpoint: body.Endpoint,
			Keys:     body.Keys,
		},
	}

	pm.records[body.UserPublicKey] = rec
	pm.saveToDiskLocked()

	log.Printf("[PushManager] Suscripción registrada para peer: %s", body.UserPublicKey)
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte("Cloud activated"))
}

// HandleSend handles POST /push/send/{targetId}
func (pm *PushManager) HandleSend(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "*")
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	targetID := strings.TrimPrefix(r.URL.Path, "/push/send/")
	targetID = strings.TrimPrefix(targetID, "/")
	if targetID == "" {
		http.Error(w, "Target ID required", http.StatusBadRequest)
		return
	}

	senderID := r.URL.Query().Get("from")
	log.Printf("[PushManager] Intento de envío de notificación de %s a %s", senderID, targetID)

	pm.mu.RLock()
	targetRec, exists := pm.records[targetID]
	var senderRec *PushSubscriptionRecord
	if senderID != "" {
		senderRec = pm.records[senderID]
	}
	pm.mu.RUnlock()

	if !exists || targetRec == nil || targetRec.Subscription == nil {
		http.Error(w, "Target offline or not subscribed", http.StatusNotFound)
		return
	}

	// Validar autenticación de emisor si se proporciona salt o si está registrado
	authHeader := r.Header.Get("X-Pingo-Auth")
	if senderRec != nil && senderRec.Salt != "" {
		expectedToken := generatePingoAuthToken(senderRec.Salt)
		if authHeader != "" && authHeader != expectedToken {
			log.Printf("[PushManager] Auth inválido para sender %s", senderID)
			http.Error(w, "Invalid Auth Token", http.StatusUnauthorized)
			return
		}
	}

	var payload map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		http.Error(w, "Failed to marshal payload", http.StatusInternalServerError)
		return
	}

	resp, err := webpush.SendNotification(payloadBytes, targetRec.Subscription, &webpush.Options{
		HTTPClient:      http.DefaultClient,
		Subscriber:      pm.subscriberEmail,
		VAPIDPublicKey:  pm.vapidPublicKey,
		VAPIDPrivateKey: pm.vapidPrivateKey,
		TTL:             30,
	})

	if err != nil {
		log.Printf("[PushManager] Error enviando WebPush a %s: %v", targetID, err)
		http.Error(w, fmt.Sprintf("Push delivery failed: %v", err), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	log.Printf("[PushManager] Notificación enviada con éxito a %s (HTTP %d)", targetID, resp.StatusCode)
	w.WriteHeader(resp.StatusCode)
	w.Write([]byte("Push sent"))
}

// HandleTest handles GET /push/test/{peerId}
func (pm *PushManager) HandleTest(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	targetID := strings.TrimPrefix(r.URL.Path, "/push/test/")
	targetID = strings.TrimPrefix(targetID, "/")

	pm.mu.RLock()
	targetRec, exists := pm.records[targetID]
	pm.mu.RUnlock()

	if !exists || targetRec == nil || targetRec.Subscription == nil {
		http.Error(w, "Target not registered", http.StatusNotFound)
		return
	}

	payloadBytes, _ := json.Marshal(map[string]string{
		"title": "Prueba de Pingo Appliance",
		"body":  "Notificación Push autohospedada funcionando correctamente.",
		"url":   "/",
	})

	resp, err := webpush.SendNotification(payloadBytes, targetRec.Subscription, &webpush.Options{
		HTTPClient:      http.DefaultClient,
		Subscriber:      pm.subscriberEmail,
		VAPIDPublicKey:  pm.vapidPublicKey,
		VAPIDPrivateKey: pm.vapidPrivateKey,
		TTL:             30,
	})
	if err != nil {
		http.Error(w, fmt.Sprintf("Test Error: %v", err), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	w.Write([]byte("Test push sent successfully"))
}

// GetSubscriptionsCount returns the number of registered peers
func (pm *PushManager) GetSubscriptionsCount() int {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return len(pm.records)
}

// GetAllSubscriptions returns a snapshot list of subscribed records
func (pm *PushManager) GetAllSubscriptions() []*PushSubscriptionRecord {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	list := make([]*PushSubscriptionRecord, 0, len(pm.records))
	for _, rec := range pm.records {
		list = append(list, rec)
	}
	return list
}
