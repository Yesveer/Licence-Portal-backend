package services

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"log"
	"math/big"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"

	"license-portal-backend/internal/config"
	"license-portal-backend/internal/db"
	"license-portal-backend/internal/models"
)

// EnsureSuperadmin creates the single portal superadmin from env on first boot.
func EnsureSuperadmin(store *db.Store, cfg *config.Config) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var existing models.AdminUser
	err := store.C("admin_users").FindOne(ctx, bson.M{"email": cfg.AdminEmail}).Decode(&existing)
	if err == nil {
		// migrate pre-role documents
		if existing.Role != models.RoleSuperadmin {
			store.C("admin_users").UpdateByID(ctx, existing.ID, bson.M{"$set": bson.M{"role": models.RoleSuperadmin}})
			log.Printf("bootstrap: upgraded %s to superadmin role", existing.Email)
		}
		return
	}
	if err != mongo.ErrNoDocuments {
		log.Fatalf("bootstrap: admin lookup failed: %v", err)
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(cfg.AdminPassword), bcrypt.DefaultCost)
	if err != nil {
		log.Fatalf("bootstrap: hash admin password failed: %v", err)
	}
	_, err = store.C("admin_users").InsertOne(ctx, models.AdminUser{
		Email:        cfg.AdminEmail,
		PasswordHash: string(hash),
		Role:         models.RoleSuperadmin,
		CreatedAt:    time.Now().UTC(),
	})
	if err != nil {
		log.Fatalf("bootstrap: create admin failed: %v", err)
	}
	log.Printf("bootstrap: superadmin %s created", cfg.AdminEmail)
}

/* ───────────── Secret generation helpers ───────────── */

// NewAPIKey returns (plaintext, sha256hex). Plaintext is shown/emailed once;
// only the hash is stored.
func NewAPIKey() (string, string) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		log.Fatalf("rand failed: %v", err)
	}
	key := "wxl_" + base64.RawURLEncoding.EncodeToString(raw)
	return key, HashAPIKey(key)
}

func HashAPIKey(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

const passwordAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789!@#$%"

// NewPassword generates the customer-superadmin initial password.
func NewPassword(n int) string {
	out := make([]byte, n)
	for i := range out {
		idx, _ := rand.Int(rand.Reader, big.NewInt(int64(len(passwordAlphabet))))
		out[i] = passwordAlphabet[idx.Int64()]
	}
	return string(out)
}

const publicIDAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

// NewPublicID returns a human-readable license id like LIC-7K2M9QRT.
func NewPublicID() string {
	out := make([]byte, 8)
	for i := range out {
		idx, _ := rand.Int(rand.Reader, big.NewInt(int64(len(publicIDAlphabet))))
		out[i] = publicIDAlphabet[idx.Int64()]
	}
	return "LIC-" + string(out)
}
