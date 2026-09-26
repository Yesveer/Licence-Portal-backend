package handlers

import (
	"context"
	"time"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo/options"

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
	var lic models.License
	h.Store.C("licenses").FindOne(ctx, bson.M{"_id": licenseID}).Decode(&lic)
	h.Store.C("license_history").InsertOne(ctx, models.LicenseHistory{
		LicenseID: licenseID, Product: lic.GetProduct(), Field: field, OldValue: oldV, NewValue: newV,
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
	if p, ok := models.ProductPlans(lic.GetProduct())[lic.Plan]; ok {
		return p.RatePerMachine
	}
	return 0
}

// licenseIDsForProduct scopes collections with no product field of their
// own (machines, quota_requests) via their license_id foreign key.
func (h *Handler) licenseIDsForProduct(ctx context.Context, product string) ([]primitive.ObjectID, error) {
	cur, err := h.Store.C("licenses").Find(ctx, bson.M{"product": product}, options.Find().SetProjection(bson.M{"_id": 1}))
	if err != nil {
		return nil, err
	}
	var docs []struct {
		ID primitive.ObjectID `bson:"_id"`
	}
	if err := cur.All(ctx, &docs); err != nil {
		return nil, err
	}
	ids := make([]primitive.ObjectID, len(docs))
	for i, d := range docs {
		ids[i] = d.ID
	}
	return ids, nil
}
