package middleware

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"go.mongodb.org/mongo-driver/bson"

	"license-portal-backend/internal/db"
	"license-portal-backend/internal/models"
	"license-portal-backend/internal/services"
)

/* ───────────── Superadmin JWT auth (portal UI) ───────────── */

func IssueAdminToken(secret, email, role string, expiryHours int) (string, error) {
	claims := jwt.MapClaims{
		"sub":  email,
		"role": role,
		"exp":  time.Now().Add(time.Duration(expiryHours) * time.Hour).Unix(),
		"iat":  time.Now().Unix(),
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(secret))
}

func AdminAuth(secret string) gin.HandlerFunc {
	return func(c *gin.Context) {
		header := c.GetHeader("Authorization")
		if !strings.HasPrefix(header, "Bearer ") {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing bearer token"})
			return
		}
		tokenStr := strings.TrimPrefix(header, "Bearer ")
		token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, jwt.ErrSignatureInvalid
			}
			return []byte(secret), nil
		})
		if err != nil || !token.Valid {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired token"})
			return
		}
		claims := token.Claims.(jwt.MapClaims)
		c.Set("admin_email", claims["sub"])
		if role, ok := claims["role"].(string); ok {
			c.Set("admin_role", role)
		}
		c.Next()
	}
}

// RequireSuperadmin gates routes that team admins must not reach
// (SMTP settings, audit log, user management).
func RequireSuperadmin() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.GetString("admin_role") != models.RoleSuperadmin {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "superadmin access required"})
			return
		}
		c.Next()
	}
}

/* ───────────── Product scope (portal UI) ───────────── */
// Reads X-Product to scope which product's data a request can see — not an auth check.

const ProductCtxKey = "product"

func ProductScope() gin.HandlerFunc {
	return func(c *gin.Context) {
		p := c.GetHeader("X-Product")
		if !models.ValidProduct(p) {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "missing or invalid X-Product header (must be 'pam' or 'epm')"})
			return
		}
		c.Set(ProductCtxKey, p)
		c.Next()
	}
}

func ProductFrom(c *gin.Context) string {
	return c.GetString(ProductCtxKey)
}

/* ───────────── Deployment API-key auth ───────────── */

const LicenseCtxKey = "license"

// APIKeyAuth resolves the X-API-Key header to a license and stores it in the
// context.
//
// A rotated key still works for a grace window (PrevAPIKeyHash / see
// config.KeyRotationGrace) so an admin has time to update the deployment's
// LICENSE_API_KEY without an instant outage; past that window it matches
// nothing, same as any other invalid key.
//
// Any license that isn't actively trial/confirmed is hard-rejected before any
// handler runs — computed against this server's clock, not the deployment's —
// so a deployment cannot keep working off a cached signed token once the
// license stops being active here: expired → 402 (billing lapsed, may still
// resolve itself), suspended/revoked → 403 (blocked by an admin action).
func APIKeyAuth(store *db.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		key := c.GetHeader("X-API-Key")
		if key == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing X-API-Key"})
			return
		}
		ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
		defer cancel()

		hash := services.HashAPIKey(key)
		now := time.Now().UTC()
		var lic models.License
		err := store.C("licenses").FindOne(ctx, bson.M{
			"$or": []bson.M{
				{"api_key_hash": hash},
				{"prev_api_key_hash": hash, "prev_api_key_expires_at": bson.M{"$gt": now}},
			},
		}).Decode(&lic)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid api key"})
			return
		}
		if lic.APIKeyHash != hash {
			// Authenticated on the grace-period key — flag it so a deployment
			// (or whoever's watching logs) knows to update LICENSE_API_KEY.
			c.Header("X-License-Key-Deprecated", "true")
		}

		if exp := lic.EffectiveExpiry(); exp != nil && now.After(*exp) &&
			(lic.Status == models.StatusTrial || lic.Status == models.StatusConfirmed) {
			store.C("licenses").UpdateByID(ctx, lic.ID, bson.M{"$set": bson.M{"status": models.StatusExpired, "updated_at": now}})
			store.C("license_history").InsertOne(ctx, models.LicenseHistory{
				LicenseID: lic.ID, Product: lic.GetProduct(), Field: "status",
				OldValue: lic.Status, NewValue: models.StatusExpired, Actor: "system",
				Reason: "expiry reached", ChangedAt: now,
			})
			lic.Status = models.StatusExpired
		}

		if lic.Status == models.StatusExpired {
			c.AbortWithStatusJSON(http.StatusPaymentRequired, gin.H{"error": "license expired", "status": lic.Status})
			return
		}
		if lic.Status != models.StatusTrial && lic.Status != models.StatusConfirmed {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "license is " + lic.Status, "status": lic.Status})
			return
		}
		c.Set(LicenseCtxKey, &lic)
		c.Next()
	}
}

func LicenseFrom(c *gin.Context) *models.License {
	v, _ := c.Get(LicenseCtxKey)
	return v.(*models.License)
}
