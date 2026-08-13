package handlers

import (
	"context"
	"time"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson/primitive"

	"license-portal-backend/internal/config"
	"license-portal-backend/internal/db"
	"license-portal-backend/internal/models"
	"license-portal-backend/internal/services"
)

type Handler struct {
	Store  *db.Store
	Cfg    *config.Config
	Signer *services.Signer
	Mailer *services.Mailer
}

func New(store *db.Store, cfg *config.Config, signer *services.Signer, mailer *services.Mailer) *Handler {
	return &Handler{Store: store, Cfg: cfg, Signer: signer, Mailer: mailer}
}

func reqCtx(c *gin.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(c.Request.Context(), 10*time.Second)
}

func (h *Handler) audit(actor, action, target, metadata string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	h.Store.C("audit_log").InsertOne(ctx, models.AuditEntry{
		Actor: actor, Action: action, Target: target, Metadata: metadata, At: time.Now().UTC(),
	})
}

func (h *Handler) history(licenseID primitive.ObjectID, field, oldV, newV, actor, reason string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	h.Store.C("license_history").InsertOne(ctx, models.LicenseHistory{
		LicenseID: licenseID, Field: field, OldValue: oldV, NewValue: newV,
		Actor: actor, Reason: reason, ChangedAt: time.Now().UTC(),
	})
}

// signedToken builds and signs the entitlement payload for a license.
func (h *Handler) signedToken(lic *models.License, company string) (string, error) {
	return h.Signer.Sign(services.LicensePayload{
		LicenseID:      lic.PublicID,
		Company:        company,
		Plan:           lic.Plan,
		MachineQuota:   lic.MachineQuota,
		Status:         lic.Status,
		UpdatesGranted: lic.UpdatesGranted,
		UpdateChannel:  lic.UpdateChannel,
		ExpiresAt:      lic.EffectiveExpiry(),
		IssuedAt:       time.Now().UTC(),
		GraceHours:     h.Cfg.OfflineGrace,
	})
}

// billingRate returns the effective ₹/machine/month for a license.
func billingRate(lic *models.License) int {
	if lic.Plan == "enterprise" && lic.CustomRate > 0 {
		return lic.CustomRate
	}
	if p, ok := models.Plans[lic.Plan]; ok {
		return p.RatePerMachine
	}
	return 0
}
