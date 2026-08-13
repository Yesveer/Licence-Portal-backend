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

/* ───────────── Deployment API-key auth ───────────── */

const LicenseCtxKey = "license"

// APIKeyAuth resolves the X-API-Key header to a license and stores it in the
// context. Revoked licenses are always rejected.
func APIKeyAuth(store *db.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		key := c.GetHeader("X-API-Key")
		if key == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing X-API-Key"})
			return
		}
		ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
		defer cancel()

		var lic models.License
		err := store.C("licenses").FindOne(ctx, bson.M{"api_key_hash": services.HashAPIKey(key)}).Decode(&lic)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid api key"})
			return
		}
		if lic.Status == models.StatusRevoked {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "license revoked"})
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
