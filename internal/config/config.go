package config

import (
	"log"
	"os"
	"strconv"

	"github.com/joho/godotenv"
)

// Config holds every runtime setting. Everything is controlled via environment
// variables (a local .env file is loaded if present).
type Config struct {
	Port        string
	MongoURI    string
	MongoDBName string

	JWTSecret      string
	JWTExpiryHours int

	// Bootstrap superadmin (created on first boot if missing)
	AdminEmail    string
	AdminPassword string

	// Ed25519 signing keys (base64 raw). If empty, a keypair is generated on
	// first boot and stored in the signing_keys collection.
	SigningPrivateKeyB64 string
	SigningPublicKeyB64  string

	// SMTP fallback (DB config, if set from the portal UI, takes precedence)
	SMTPHost string
	SMTPPort int
	SMTPUser string
	SMTPPass string
	SMTPFrom string

	// Trial defaults (Community plan)
	TrialDays    int
	TrialQuota   int
	CORSOrigins  string
	PortalName   string
	OfflineGrace int // hours a deployment may run on a cached license

	// KeyRotationGrace: hours the OLD api key keeps working after a rotation,
	// so an admin has time to update the deployment's LICENSE_API_KEY without
	// an instant outage. 0 disables the grace window (hard cutover).
	KeyRotationGrace int
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func getenvInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func Load() *Config {
	if err := godotenv.Load(); err == nil {
		log.Println("config: loaded .env file")
	}

	cfg := &Config{
		Port:        getenv("PORT", "8080"),
		MongoURI:    getenv("MONGO_URI", "mongodb://localhost:27017"),
		MongoDBName: getenv("MONGO_DB", "license_portal"),

		JWTSecret:      getenv("JWT_SECRET", ""),
		JWTExpiryHours: getenvInt("JWT_EXPIRY_HOURS", 24),

		AdminEmail:    getenv("ADMIN_EMAIL", "admin@webxterm.me"),
		AdminPassword: getenv("ADMIN_PASSWORD", ""),

		SigningPrivateKeyB64: getenv("LICENSE_SIGNING_PRIVATE_KEY", ""),
		SigningPublicKeyB64:  getenv("LICENSE_SIGNING_PUBLIC_KEY", ""),

		SMTPHost: getenv("SMTP_HOST", ""),
		SMTPPort: getenvInt("SMTP_PORT", 587),
		SMTPUser: getenv("SMTP_USER", ""),
		SMTPPass: getenv("SMTP_PASS", ""),
		SMTPFrom: getenv("SMTP_FROM", "licensing@webxterm.me"),

		TrialDays:    getenvInt("TRIAL_DAYS", 30),
		TrialQuota:   getenvInt("TRIAL_MACHINE_QUOTA", 10),
		CORSOrigins:  getenv("CORS_ORIGINS", "http://localhost:3000"),
		PortalName:   getenv("PORTAL_NAME", "WebXTerm Licensing Portal"),
		OfflineGrace: getenvInt("OFFLINE_GRACE_HOURS", 72),

		KeyRotationGrace: getenvInt("KEY_ROTATION_GRACE_HOURS", 24),
	}

	if cfg.JWTSecret == "" {
		log.Fatal("config: JWT_SECRET is required")
	}
	if cfg.AdminPassword == "" {
		log.Fatal("config: ADMIN_PASSWORD is required (bootstrap superadmin)")
	}
	return cfg
}
