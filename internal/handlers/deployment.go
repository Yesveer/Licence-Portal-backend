package handlers

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"

	"license-portal-backend/internal/middleware"
	"license-portal-backend/internal/models"
)

// checkLifecycle flips a trial/paid license to expired when its date passed.
// Returns the (possibly updated) status.
func (h *Handler) checkLifecycle(c *gin.Context, lic *models.License) string {
	exp := lic.EffectiveExpiry()
	if exp != nil && time.Now().After(*exp) && (lic.Status == models.StatusTrial || lic.Status == models.StatusConfirmed) {
		ctx, cancel := reqCtx(c)
		defer cancel()
		h.Store.C("licenses").UpdateByID(ctx, lic.ID, bson.M{"$set": bson.M{"status": models.StatusExpired, "updated_at": time.Now().UTC()}})
		h.history(lic.ID, "status", lic.Status, models.StatusExpired, "system", "expiry reached")
		lic.Status = models.StatusExpired
	}
	return lic.Status
}

func (h *Handler) companyOf(c *gin.Context, lic *models.License) string {
	ctx, cancel := reqCtx(c)
	defer cancel()
	var cust models.Customer
	h.Store.C("customers").FindOne(ctx, bson.M{"_id": lic.CustomerID}).Decode(&cust)
	return cust.CompanyName
}

/* ───────────── POST /api/v1/activate ───────────── */

func (h *Handler) Activate(c *gin.Context) {
	var req struct {
		DeploymentURL  string `json:"deployment_url"`
		ProductVersion string `json:"product_version"`
	}
	c.ShouldBindJSON(&req) // body optional

	lic := middleware.LicenseFrom(c)
	h.checkLifecycle(c, lic)

	ctx, cancel := reqCtx(c)
	defer cancel()
	now := time.Now().UTC()
	set := bson.M{"last_seen_at": now, "updated_at": now}
	if lic.ActivatedAt == nil {
		set["activated_at"] = now
	}
	if req.DeploymentURL != "" {
		set["deployment_url"] = req.DeploymentURL
	}
	if req.ProductVersion != "" {
		set["product_version"] = req.ProductVersion
	}
	h.Store.C("licenses").UpdateByID(ctx, lic.ID, bson.M{"$set": set})
	h.audit("deployment:"+lic.PublicID, "activate", lic.PublicID, req.DeploymentURL)

	token, err := h.signedToken(lic, h.companyOf(c, lic))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "signing failed"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"license_token": token,
		"public_key":    h.Signer.PublicKeyB64(),
		"license": gin.H{
			"public_id":       lic.PublicID,
			"plan":            lic.Plan,
			"machine_quota":   lic.MachineQuota,
			"status":          lic.Status,
			"updates_granted": lic.UpdatesGranted,
			"expires_at":      lic.EffectiveExpiry(),
		},
	})
}

/* ───────────── GET /api/v1/license ───────────── */

func (h *Handler) FetchLicense(c *gin.Context) {
	lic := middleware.LicenseFrom(c)
	h.checkLifecycle(c, lic)

	ctx, cancel := reqCtx(c)
	defer cancel()
	h.Store.C("licenses").UpdateByID(ctx, lic.ID, bson.M{"$set": bson.M{"last_seen_at": time.Now().UTC()}})

	token, err := h.signedToken(lic, h.companyOf(c, lic))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "signing failed"})
		return
	}
	used, _ := h.Store.C("machines").CountDocuments(ctx, bson.M{"license_id": lic.ID, "active": true})
	c.JSON(http.StatusOK, gin.H{
		"license_token": token,
		"machines_used": used,
		"machine_quota": lic.MachineQuota,
		"status":        lic.Status,
	})
}

/* ───────────── POST /api/v1/machines — HARD quota block ───────────── */

func (h *Handler) RegisterMachine(c *gin.Context) {
	var req struct {
		Fingerprint string `json:"fingerprint" binding:"required"`
		Name        string `json:"name"`
		TenantRef   string `json:"tenant_ref"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	lic := middleware.LicenseFrom(c)
	status := h.checkLifecycle(c, lic)

	// Only active licenses may create machines. Expired/suspended → read-only.
	if status != models.StatusTrial && status != models.StatusConfirmed {
		c.JSON(http.StatusForbidden, gin.H{"allowed": false, "error": "license is " + status + " — machine creation blocked"})
		return
	}

	ctx, cancel := reqCtx(c)
	defer cancel()
	now := time.Now().UTC()

	// Re-registering a known fingerprint just refreshes it (idempotent).
	res := h.Store.C("machines").FindOneAndUpdate(ctx,
		bson.M{"license_id": lic.ID, "fingerprint": req.Fingerprint},
		bson.M{"$set": bson.M{"last_heartbeat": now, "active": true, "name": req.Name, "tenant_ref": req.TenantRef}},
	)
	if res.Err() == nil {
		used, _ := h.Store.C("machines").CountDocuments(ctx, bson.M{"license_id": lic.ID, "active": true})
		c.JSON(http.StatusOK, gin.H{"allowed": true, "machines_used": used, "machine_quota": lic.MachineQuota, "existing": true})
		return
	}
	if res.Err() != mongo.ErrNoDocuments {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "lookup failed"})
		return
	}

	// HARD BLOCK: count active fingerprints; at or over quota → deny.
	// The unique (license_id, fingerprint) index prevents duplicate inserts;
	// the count check enforces the ceiling.
	used, err := h.Store.C("machines").CountDocuments(ctx, bson.M{"license_id": lic.ID, "active": true})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "count failed"})
		return
	}
	if lic.MachineQuota > 0 && used >= int64(lic.MachineQuota) {
		h.audit("deployment:"+lic.PublicID, "machine_denied", req.Fingerprint, "quota reached")
		c.JSON(http.StatusForbidden, gin.H{
			"allowed":       false,
			"machines_used": used,
			"machine_quota": lic.MachineQuota,
			"error":         "machine quota reached — request a quota increase or upgrade the plan",
		})
		return
	}

	_, err = h.Store.C("machines").InsertOne(ctx, models.Machine{
		LicenseID: lic.ID, Fingerprint: req.Fingerprint, Name: req.Name,
		TenantRef: req.TenantRef, Active: true, FirstSeen: now, LastHeartbeat: now,
	})
	if err != nil {
		if mongo.IsDuplicateKeyError(err) { // raced with another register of same fingerprint
			c.JSON(http.StatusOK, gin.H{"allowed": true, "existing": true})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "insert failed"})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"allowed": true, "machines_used": used + 1, "machine_quota": lic.MachineQuota})
}

/* ───────────── DELETE /api/v1/machines/:fingerprint ───────────── */

func (h *Handler) DeactivateMachine(c *gin.Context) {
	lic := middleware.LicenseFrom(c)
	ctx, cancel := reqCtx(c)
	defer cancel()

	res, err := h.Store.C("machines").UpdateOne(ctx,
		bson.M{"license_id": lic.ID, "fingerprint": c.Param("fingerprint")},
		bson.M{"$set": bson.M{"active": false, "last_heartbeat": time.Now().UTC()}},
	)
	if err != nil || res.MatchedCount == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "machine not found"})
		return
	}
	h.audit("deployment:"+lic.PublicID, "machine_deactivated", c.Param("fingerprint"), "")
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

/* ───────────── POST /api/v1/heartbeat ───────────── */

func (h *Handler) Heartbeat(c *gin.Context) {
	var req struct {
		Machines       []string `json:"machines"` // active fingerprints
		ProductVersion string   `json:"product_version"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	lic := middleware.LicenseFrom(c)
	status := h.checkLifecycle(c, lic)

	ctx, cancel := reqCtx(c)
	defer cancel()
	now := time.Now().UTC()

	set := bson.M{"last_seen_at": now}
	if req.ProductVersion != "" {
		set["product_version"] = req.ProductVersion
	}
	h.Store.C("licenses").UpdateByID(ctx, lic.ID, bson.M{"$set": set})

	if len(req.Machines) > 0 {
		h.Store.C("machines").UpdateMany(ctx,
			bson.M{"license_id": lic.ID, "fingerprint": bson.M{"$in": req.Machines}},
			bson.M{"$set": bson.M{"last_heartbeat": now, "active": true}},
		)
		// fingerprints not reported are marked inactive
		h.Store.C("machines").UpdateMany(ctx,
			bson.M{"license_id": lic.ID, "fingerprint": bson.M{"$nin": req.Machines}, "active": true},
			bson.M{"$set": bson.M{"active": false}},
		)
	}
	used, _ := h.Store.C("machines").CountDocuments(ctx, bson.M{"license_id": lic.ID, "active": true})
	c.JSON(http.StatusOK, gin.H{
		"status":        status,
		"machines_used": used,
		"machine_quota": lic.MachineQuota,
		"refresh":       status != models.StatusTrial && status != models.StatusConfirmed, // hint: re-fetch license
	})
}

/* ───────────── POST /api/v1/quota-request ───────────── */

func (h *Handler) CreateQuotaRequest(c *gin.Context) {
	var req struct {
		RequestedDelta int    `json:"requested_delta" binding:"required"`
		Reason         string `json:"reason"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.RequestedDelta <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "requested_delta must be positive"})
		return
	}
	lic := middleware.LicenseFrom(c)
	ctx, cancel := reqCtx(c)
	defer cancel()

	// one pending request at a time
	pending, _ := h.Store.C("quota_requests").CountDocuments(ctx, bson.M{"license_id": lic.ID, "status": "pending"})
	if pending > 0 {
		c.JSON(http.StatusConflict, gin.H{"error": "a quota request is already pending"})
		return
	}
	qr := models.QuotaRequest{
		LicenseID: lic.ID, RequestedDelta: req.RequestedDelta,
		Reason: req.Reason, Status: "pending", RequestedAt: time.Now().UTC(),
	}
	if _, err := h.Store.C("quota_requests").InsertOne(ctx, qr); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "insert failed"})
		return
	}
	h.audit("deployment:"+lic.PublicID, "quota_request", lic.PublicID, req.Reason)
	c.JSON(http.StatusCreated, gin.H{"ok": true, "status": "pending"})
}

/* ───────────── GET /api/v1/update-channel ───────────── */

func (h *Handler) UpdateChannel(c *gin.Context) {
	lic := middleware.LicenseFrom(c)
	h.checkLifecycle(c, lic)
	if !lic.UpdatesGranted {
		c.JSON(http.StatusForbidden, gin.H{"updates_granted": false, "error": "updates not granted for this license"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"updates_granted": true, "channel": lic.UpdateChannel})
}

/* ───────────── GET /api/v1/public-key (no auth) ───────────── */

func (h *Handler) PublicKey(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"algorithm": "ed25519", "public_key": h.Signer.PublicKeyB64()})
}
