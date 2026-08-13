package services

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"

	"license-portal-backend/internal/db"
	"license-portal-backend/internal/models"
)

// Signer issues Ed25519-signed license tokens. The private key never leaves
// the portal; deployments verify with the bundled public key.
type Signer struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

// LicensePayload is what a deployment receives and enforces.
type LicensePayload struct {
	LicenseID      string     `json:"license_id"`
	Company        string     `json:"company"`
	Plan           string     `json:"plan"`
	MachineQuota   int        `json:"machine_quota"`
	Status         string     `json:"status"`
	UpdatesGranted bool       `json:"updates_granted"`
	UpdateChannel  string     `json:"update_channel,omitempty"`
	ExpiresAt      *time.Time `json:"expires_at,omitempty"`
	IssuedAt       time.Time  `json:"issued_at"`
	GraceHours     int        `json:"grace_hours"`
}

// NewSigner loads keys from env (base64 raw keys) or falls back to a keypair
// persisted in the signing_keys collection, generating one on first boot.
func NewSigner(store *db.Store, privB64, pubB64 string) *Signer {
	if privB64 != "" && pubB64 != "" {
		priv, err1 := base64.StdEncoding.DecodeString(privB64)
		pub, err2 := base64.StdEncoding.DecodeString(pubB64)
		if err1 != nil || err2 != nil || len(priv) != ed25519.PrivateKeySize || len(pub) != ed25519.PublicKeySize {
			log.Fatal("signing: invalid LICENSE_SIGNING_PRIVATE_KEY / LICENSE_SIGNING_PUBLIC_KEY (want base64 raw ed25519 keys)")
		}
		log.Println("signing: using keys from environment")
		return &Signer{priv: priv, pub: pub}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var keys models.SigningKeys
	err := store.C("signing_keys").FindOne(ctx, bson.M{"_id": "ed25519"}).Decode(&keys)
	if err == mongo.ErrNoDocuments {
		pub, priv, genErr := ed25519.GenerateKey(rand.Reader)
		if genErr != nil {
			log.Fatalf("signing: keygen failed: %v", genErr)
		}
		keys = models.SigningKeys{
			ID:         "ed25519",
			PrivateB64: base64.StdEncoding.EncodeToString(priv),
			PublicB64:  base64.StdEncoding.EncodeToString(pub),
			CreatedAt:  time.Now().UTC(),
		}
		if _, insErr := store.C("signing_keys").InsertOne(ctx, keys); insErr != nil {
			log.Fatalf("signing: persist keys failed: %v", insErr)
		}
		log.Printf("signing: generated new Ed25519 keypair. PUBLIC KEY (bundle into product): %s", keys.PublicB64)
	} else if err != nil {
		log.Fatalf("signing: load keys failed: %v", err)
	}

	priv, _ := base64.StdEncoding.DecodeString(keys.PrivateB64)
	pub, _ := base64.StdEncoding.DecodeString(keys.PublicB64)
	return &Signer{priv: priv, pub: pub}
}

func (s *Signer) PublicKeyB64() string {
	return base64.StdEncoding.EncodeToString(s.pub)
}

// Sign returns a token of the form base64url(payload).base64url(signature).
func (s *Signer) Sign(p LicensePayload) (string, error) {
	body, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	sig := ed25519.Sign(s.priv, body)
	return fmt.Sprintf("%s.%s",
		base64.RawURLEncoding.EncodeToString(body),
		base64.RawURLEncoding.EncodeToString(sig)), nil
}
