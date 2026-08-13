package main

import (
	"context"
	"log"
	"strings"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"

	"license-portal-backend/internal/config"
	"license-portal-backend/internal/db"
	"license-portal-backend/internal/handlers"
	"license-portal-backend/internal/middleware"
	"license-portal-backend/internal/models"
	"license-portal-backend/internal/services"
)

func main() {
	cfg := config.Load()
	store := db.Connect(cfg.MongoURI, cfg.MongoDBName)

	services.EnsureSuperadmin(store, cfg)
	signer := services.NewSigner(store, cfg.SigningPrivateKeyB64, cfg.SigningPublicKeyB64)
	mailer := services.NewMailer(store, cfg)
	h := handlers.New(store, cfg, signer, mailer)

	go expiryReminderLoop(store, cfg, mailer)

	r := gin.Default()
	corsCfg := cors.Config{
		AllowMethods: []string{"GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders: []string{"Origin", "Content-Type", "Authorization", "X-API-Key"},
		MaxAge:       12 * time.Hour,
	}
	if strings.TrimSpace(cfg.CORSOrigins) == "*" {
		// allow all origins (auth is via Bearer/API-key headers, not cookies)
		corsCfg.AllowAllOrigins = true
	} else {
		corsCfg.AllowOrigins = strings.Split(cfg.CORSOrigins, ",")
		corsCfg.AllowCredentials = true
	}
	r.Use(cors.New(corsCfg))

	r.GET("/health", func(c *gin.Context) { c.JSON(200, gin.H{"ok": true, "service": "license-portal"}) })

	// ── Superadmin portal API (JWT) ──
	admin := r.Group("/api/admin")
	admin.POST("/login", h.Login)
	authed := admin.Group("", middleware.AdminAuth(cfg.JWTSecret))
	{
		authed.GET("/dashboard", h.Dashboard)
		authed.GET("/plans", h.ListPlans)
		authed.POST("/customers", h.OnboardCustomer)
		authed.GET("/licenses", h.ListLicenses)
		authed.GET("/licenses/:id", h.GetLicense)
		authed.PATCH("/licenses/:id", h.UpdateLicense)
		authed.POST("/licenses/:id/rotate-key", h.RotateAPIKey)
		authed.POST("/licenses/:id/payments", h.RecordPayment)
		authed.GET("/quota-requests", h.ListQuotaRequests)
		authed.POST("/quota-requests/:id/decide", h.DecideQuotaRequest)

		// superadmin-only: SMTP settings, audit log, user management
		sa := authed.Group("", middleware.RequireSuperadmin())
		{
			sa.GET("/smtp", h.GetSMTP)
			sa.PUT("/smtp", h.SaveSMTP)
			sa.POST("/smtp/test", h.TestSMTP)
			sa.GET("/audit", h.ListAudit)
			sa.GET("/users", h.ListUsers)
			sa.POST("/users", h.CreateUser)
			sa.PATCH("/users/:id", h.UpdateUser)
			sa.DELETE("/users/:id", h.DeleteUser)
		}
	}

	// ── Deployment-facing API (X-API-Key) ──
	r.GET("/api/v1/public-key", h.PublicKey)
	v1 := r.Group("/api/v1", middleware.APIKeyAuth(store))
	{
		v1.POST("/activate", h.Activate)
		v1.GET("/license", h.FetchLicense)
		v1.POST("/machines", h.RegisterMachine)
		v1.DELETE("/machines/:fingerprint", h.DeactivateMachine)
		v1.POST("/heartbeat", h.Heartbeat)
		v1.POST("/quota-request", h.CreateQuotaRequest)
		v1.GET("/update-channel", h.UpdateChannel)
	}

	log.Printf("license-portal backend listening on :%s", cfg.Port)
	if err := r.Run(":" + cfg.Port); err != nil {
		log.Fatal(err)
	}
}

// expiryReminderLoop sends trial-expiry reminder emails (T-7 and T-1) once a
// day, and flips overdue licenses to expired.
func expiryReminderLoop(store *db.Store, cfg *config.Config, mailer *services.Mailer) {
	tick := time.NewTicker(12 * time.Hour)
	defer tick.Stop()
	for {
		runExpiryPass(store, cfg, mailer)
		<-tick.C
	}
}

func runExpiryPass(store *db.Store, cfg *config.Config, mailer *services.Mailer) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	now := time.Now().UTC()

	// expire overdue trials/paid licenses
	store.C("licenses").UpdateMany(ctx,
		bson.M{"status": models.StatusTrial, "trial_expires_at": bson.M{"$lt": now}},
		bson.M{"$set": bson.M{"status": models.StatusExpired, "updated_at": now}},
	)
	store.C("licenses").UpdateMany(ctx,
		bson.M{"status": models.StatusConfirmed, "expires_at": bson.M{"$lt": now}},
		bson.M{"$set": bson.M{"status": models.StatusExpired, "updated_at": now}},
	)

	// remind trials expiring within 7 days (at most one mail per 24h pass)
	cur, err := store.C("licenses").Find(ctx, bson.M{
		"status":           models.StatusTrial,
		"trial_expires_at": bson.M{"$gte": now, "$lte": now.Add(7 * 24 * time.Hour)},
		"$or": []bson.M{
			{"last_reminder_at": bson.M{"$exists": false}},
			{"last_reminder_at": bson.M{"$lt": now.Add(-23 * time.Hour)}},
		},
	})
	if err != nil {
		log.Printf("expiry pass: query failed: %v", err)
		return
	}
	var lics []models.License
	if err := cur.All(ctx, &lics); err != nil {
		return
	}
	for _, lic := range lics {
		var cust models.Customer
		if err := store.C("customers").FindOne(ctx, bson.M{"_id": lic.CustomerID}).Decode(&cust); err != nil {
			continue
		}
		daysLeft := int(time.Until(*lic.TrialExpiresAt).Hours()/24) + 1
		subject, body := services.ExpiryReminderEmail(cfg.PortalName, cust.CompanyName, daysLeft)
		mailer.SendAsync(cust.Email, subject, body)
		store.C("licenses").UpdateByID(ctx, lic.ID, bson.M{"$set": bson.M{"last_reminder_at": now}})
	}
}
