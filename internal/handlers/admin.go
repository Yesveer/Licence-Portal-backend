package handlers

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"

	"license-portal-backend/internal/middleware"
	"license-portal-backend/internal/models"
	"license-portal-backend/internal/services"
)

/* ───────────── Auth ───────────── */

func (h *Handler) Login(c *gin.Context) {
	var req struct {
		Email    string `json:"email" binding:"required"`
		Password string `json:"password" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	ctx, cancel := reqCtx(c)
	defer cancel()

	var admin models.AdminUser
	if err := h.Store.C("admin_users").FindOne(ctx, bson.M{"email": req.Email}).Decode(&admin); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(admin.PasswordHash), []byte(req.Password)) != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}
	if admin.Role == "" {
		admin.Role = models.RoleSuperadmin // pre-role documents
	}
	token, err := middleware.IssueAdminToken(h.Cfg.JWTSecret, admin.Email, admin.Role, h.Cfg.JWTExpiryHours)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "token issue failed"})
		return
	}
	h.audit(admin.Email, "login", "portal", admin.Role)
	c.JSON(http.StatusOK, gin.H{"token": token, "email": admin.Email, "role": admin.Role})
}

/* ───────────── Plans ───────────── */

func (h *Handler) ListPlans(c *gin.Context) {
	out := make([]models.Plan, 0, len(models.PlanOrder))
	for _, id := range models.PlanOrder {
		out = append(out, models.Plans[id])
	}
	c.JSON(http.StatusOK, gin.H{"plans": out})
}

/* ───────────── Dashboard ───────────── */

func (h *Handler) Dashboard(c *gin.Context) {
	ctx, cancel := reqCtx(c)
	defer cancel()
	lic := h.Store.C("licenses")

	total, _ := lic.CountDocuments(ctx, bson.M{})
	trial, _ := lic.CountDocuments(ctx, bson.M{"status": models.StatusTrial})
	paid, _ := lic.CountDocuments(ctx, bson.M{"status": models.StatusConfirmed})
	suspended, _ := lic.CountDocuments(ctx, bson.M{"status": bson.M{"$in": []string{models.StatusSuspended, models.StatusExpired}}})
	expiring, _ := lic.CountDocuments(ctx, bson.M{
		"status":           models.StatusTrial,
		"trial_expires_at": bson.M{"$lte": time.Now().Add(7 * 24 * time.Hour), "$gte": time.Now()},
	})
	machines, _ := h.Store.C("machines").CountDocuments(ctx, bson.M{"active": true})
	pendingQuota, _ := h.Store.C("quota_requests").CountDocuments(ctx, bson.M{"status": "pending"})
	unpaid, _ := lic.CountDocuments(ctx, bson.M{"status": models.StatusConfirmed, "amount_paid": false})

	c.JSON(http.StatusOK, gin.H{
		"customers":              total,
		"on_trial":               trial,
		"paid":                   paid,
		"suspended":              suspended,
		"expiring_7d":            expiring,
		"active_machines":        machines,
		"pending_quota_requests": pendingQuota,
		"unpaid_licenses":        unpaid,
	})
}

/* ───────────── Onboard customer ───────────── */

func (h *Handler) OnboardCustomer(c *gin.Context) {
	var req struct {
		CompanyName    string `json:"company_name" binding:"required"`
		Email          string `json:"email" binding:"required,email"`
		Phone          string `json:"phone"`
		DeploymentURL  string `json:"deployment_url"`
		Plan           string `json:"plan"`
		MachineQuota   int    `json:"machine_quota"`
		CustomRate     int    `json:"custom_rate"`
		UpdatesGranted bool   `json:"updates_granted"`
		UpdateChannel  string `json:"update_channel"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.Plan == "" {
		req.Plan = "community"
	}
	plan, ok := models.Plans[req.Plan]
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "unknown plan"})
		return
	}
	// Default and validate quota against the plan ceiling.
	if req.MachineQuota <= 0 {
		if plan.Trial {
			req.MachineQuota = h.Cfg.TrialQuota
		} else if plan.MaxMachines > 0 {
			req.MachineQuota = plan.MaxMachines
		} else {
			c.JSON(http.StatusBadRequest, gin.H{"error": "machine_quota required for enterprise"})
			return
		}
	}
	if plan.MaxMachines > 0 && req.MachineQuota > plan.MaxMachines {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("plan %s allows at most %d machines", plan.Name, plan.MaxMachines)})
		return
	}

	ctx, cancel := reqCtx(c)
	defer cancel()
	now := time.Now().UTC()
	actor := c.GetString("admin_email")

	cust := models.Customer{CompanyName: req.CompanyName, Email: req.Email, Phone: req.Phone, CreatedAt: now}
	custRes, err := h.Store.C("customers").InsertOne(ctx, cust)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "customer create failed"})
		return
	}
	custID := custRes.InsertedID.(primitive.ObjectID)

	apiKey, apiKeyHash := services.NewAPIKey()
	password := services.NewPassword(14)
	passHash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

	licDoc := models.License{
		CustomerID:     custID,
		PublicID:       services.NewPublicID(),
		Plan:           req.Plan,
		MachineQuota:   req.MachineQuota,
		CustomRate:     req.CustomRate,
		UpdatesGranted: req.UpdatesGranted,
		UpdateChannel:  req.UpdateChannel,
		DeploymentURL:  req.DeploymentURL,
		APIKeyHash:     apiKeyHash,
		AmountPaid:     false,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	if plan.Trial {
		licDoc.Status = models.StatusTrial
		exp := now.Add(time.Duration(h.Cfg.TrialDays) * 24 * time.Hour)
		licDoc.TrialExpiresAt = &exp
	} else {
		licDoc.Status = models.StatusConfirmed
	}

	licRes, err := h.Store.C("licenses").InsertOne(ctx, licDoc)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "license create failed"})
		return
	}
	licID := licRes.InsertedID.(primitive.ObjectID)

	// Customer-superadmin initial credentials live on the customer record.
	h.Store.C("customers").UpdateByID(ctx, custID, bson.M{"$set": bson.M{"password_hash": string(passHash)}})

	h.history(licID, "created", "", fmt.Sprintf("plan=%s quota=%d", req.Plan, req.MachineQuota), actor, "onboarding")
	h.audit(actor, "onboard_customer", licDoc.PublicID, req.CompanyName)

	subject, body := services.OnboardingEmail(
		h.Cfg.PortalName, req.CompanyName, req.Email, password, apiKey,
		licDoc.PublicID, req.DeploymentURL, req.MachineQuota, h.Cfg.TrialDays,
	)
	h.Mailer.SendAsync(req.Email, subject, body)

	c.JSON(http.StatusCreated, gin.H{
		"customer_id": custID.Hex(),
		"license_id":  licID.Hex(),
		"public_id":   licDoc.PublicID,
		"api_key":     apiKey,   // shown once
		"password":    password, // shown once, emailed
		"status":      licDoc.Status,
		"quota":       licDoc.MachineQuota,
	})
}

/* ───────────── License listing & detail ───────────── */

func (h *Handler) ListLicenses(c *gin.Context) {
	ctx, cancel := reqCtx(c)
	defer cancel()

	filter := bson.M{}
	if s := c.Query("status"); s != "" {
		filter["status"] = s
	}
	if p := c.Query("plan"); p != "" {
		filter["plan"] = p
	}

	cur, err := h.Store.C("licenses").Find(ctx, filter, options.Find().SetSort(bson.D{{Key: "created_at", Value: -1}}).SetLimit(500))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "query failed"})
		return
	}
	var lics []models.License
	if err := cur.All(ctx, &lics); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "decode failed"})
		return
	}

	// join customers + live machine counts
	type row struct {
		models.License
		Company      string `json:"company_name"`
		Email        string `json:"email"`
		MachinesUsed int64  `json:"machines_used"`
	}
	search := c.Query("search")
	out := make([]row, 0, len(lics))
	for _, l := range lics {
		var cust models.Customer
		h.Store.C("customers").FindOne(ctx, bson.M{"_id": l.CustomerID}).Decode(&cust)
		if search != "" && !containsFold(cust.CompanyName, search) && !containsFold(cust.Email, search) && !containsFold(l.PublicID, search) {
			continue
		}
		used, _ := h.Store.C("machines").CountDocuments(ctx, bson.M{"license_id": l.ID, "active": true})
		out = append(out, row{License: l, Company: cust.CompanyName, Email: cust.Email, MachinesUsed: used})
	}
	c.JSON(http.StatusOK, gin.H{"licenses": out})
}

func containsFold(haystack, needle string) bool {
	h, n := []rune(haystack), []rune(needle)
	if len(n) == 0 || len(n) > len(h) {
		return len(n) == 0
	}
	lower := func(r rune) rune {
		if r >= 'A' && r <= 'Z' {
			return r + 32
		}
		return r
	}
outer:
	for i := 0; i+len(n) <= len(h); i++ {
		for j := range n {
			if lower(h[i+j]) != lower(n[j]) {
				continue outer
			}
		}
		return true
	}
	return false
}

func (h *Handler) GetLicense(c *gin.Context) {
	ctx, cancel := reqCtx(c)
	defer cancel()

	id, err := primitive.ObjectIDFromHex(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "bad id"})
		return
	}
	var lic models.License
	if err := h.Store.C("licenses").FindOne(ctx, bson.M{"_id": id}).Decode(&lic); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "license not found"})
		return
	}
	var cust models.Customer
	h.Store.C("customers").FindOne(ctx, bson.M{"_id": lic.CustomerID}).Decode(&cust)

	// initialized (non-nil) so empty results serialise as [] instead of null
	machines := []models.Machine{}
	cur, _ := h.Store.C("machines").Find(ctx, bson.M{"license_id": lic.ID}, options.Find().SetSort(bson.D{{Key: "first_seen", Value: -1}}))
	cur.All(ctx, &machines)

	history := []models.LicenseHistory{}
	cur, _ = h.Store.C("license_history").Find(ctx, bson.M{"license_id": lic.ID}, options.Find().SetSort(bson.D{{Key: "changed_at", Value: -1}}))
	cur.All(ctx, &history)

	payments := []models.Payment{}
	cur, _ = h.Store.C("payments").Find(ctx, bson.M{"license_id": lic.ID}, options.Find().SetSort(bson.D{{Key: "paid_at", Value: -1}}))
	cur.All(ctx, &payments)

	quotaReqs := []models.QuotaRequest{}
	cur, _ = h.Store.C("quota_requests").Find(ctx, bson.M{"license_id": lic.ID}, options.Find().SetSort(bson.D{{Key: "requested_at", Value: -1}}))
	cur.All(ctx, &quotaReqs)

	activeMachines := 0
	for _, m := range machines {
		if m.Active {
			activeMachines++
		}
	}
	rate := billingRate(&lic)
	totalPaid := 0
	for _, p := range payments {
		totalPaid += p.Amount
	}

	c.JSON(http.StatusOK, gin.H{
		"license":  lic,
		"customer": cust,
		"machines": machines,
		"history":  history,
		"payments": payments,
		"quota_requests": quotaReqs,
		"billing": gin.H{
			"rate_per_machine": rate,
			"machines_used":    activeMachines,
			"monthly_cost":     rate * lic.MachineQuota, // plan-based: quota × rate, no pay-as-you-go
			"total_paid":       totalPaid,
			"amount_paid_flag": lic.AmountPaid,
		},
	})
}

/* ───────────── Update license ───────────── */

func (h *Handler) UpdateLicense(c *gin.Context) {
	var req struct {
		MachineQuota   *int    `json:"machine_quota"`
		Plan           *string `json:"plan"`
		Status         *string `json:"status"`
		UpdatesGranted *bool   `json:"updates_granted"`
		UpdateChannel  *string `json:"update_channel"`
		CustomRate     *int    `json:"custom_rate"`
		DeploymentURL  *string `json:"deployment_url"`
		ExtendDays     *int    `json:"extend_days"` // extend trial/paid expiry
		AmountPaid     *bool   `json:"amount_paid"`
		Reason         string  `json:"reason"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	id, err := primitive.ObjectIDFromHex(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "bad id"})
		return
	}
	ctx, cancel := reqCtx(c)
	defer cancel()

	var lic models.License
	if err := h.Store.C("licenses").FindOne(ctx, bson.M{"_id": id}).Decode(&lic); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "license not found"})
		return
	}

	actor := c.GetString("admin_email")
	set := bson.M{"updated_at": time.Now().UTC()}

	targetPlan := lic.Plan
	if req.Plan != nil && *req.Plan != lic.Plan {
		if _, ok := models.Plans[*req.Plan]; !ok {
			c.JSON(http.StatusBadRequest, gin.H{"error": "unknown plan"})
			return
		}
		targetPlan = *req.Plan
		set["plan"] = targetPlan
		h.history(id, "plan", lic.Plan, targetPlan, actor, req.Reason)
	}
	if req.MachineQuota != nil && *req.MachineQuota != lic.MachineQuota {
		plan := models.Plans[targetPlan]
		if plan.MaxMachines > 0 && *req.MachineQuota > plan.MaxMachines {
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("plan %s allows at most %d machines — upgrade the plan first", plan.Name, plan.MaxMachines)})
			return
		}
		if *req.MachineQuota < 1 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "quota must be >= 1"})
			return
		}
		set["machine_quota"] = *req.MachineQuota
		h.history(id, "machine_quota", strconv.Itoa(lic.MachineQuota), strconv.Itoa(*req.MachineQuota), actor, req.Reason)
	}
	if req.Status != nil && *req.Status != lic.Status {
		valid := map[string]bool{models.StatusTrial: true, models.StatusConfirmed: true, models.StatusSuspended: true, models.StatusExpired: true, models.StatusRevoked: true}
		if !valid[*req.Status] {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid status"})
			return
		}
		set["status"] = *req.Status
		// trial → confirmed sets a paid expiry a month out by default
		if lic.Status == models.StatusTrial && *req.Status == models.StatusConfirmed && lic.ExpiresAt == nil {
			exp := time.Now().UTC().Add(30 * 24 * time.Hour)
			set["expires_at"] = exp
		}
		h.history(id, "status", lic.Status, *req.Status, actor, req.Reason)
	}
	if req.UpdatesGranted != nil && *req.UpdatesGranted != lic.UpdatesGranted {
		set["updates_granted"] = *req.UpdatesGranted
		h.history(id, "updates_granted", strconv.FormatBool(lic.UpdatesGranted), strconv.FormatBool(*req.UpdatesGranted), actor, req.Reason)
	}
	if req.UpdateChannel != nil && *req.UpdateChannel != lic.UpdateChannel {
		set["update_channel"] = *req.UpdateChannel
		h.history(id, "update_channel", lic.UpdateChannel, *req.UpdateChannel, actor, req.Reason)
	}
	if req.CustomRate != nil {
		set["custom_rate"] = *req.CustomRate
		h.history(id, "custom_rate", strconv.Itoa(lic.CustomRate), strconv.Itoa(*req.CustomRate), actor, req.Reason)
	}
	if req.DeploymentURL != nil {
		set["deployment_url"] = *req.DeploymentURL
	}
	if req.AmountPaid != nil && *req.AmountPaid != lic.AmountPaid {
		set["amount_paid"] = *req.AmountPaid
		h.history(id, "amount_paid", strconv.FormatBool(lic.AmountPaid), strconv.FormatBool(*req.AmountPaid), actor, req.Reason)
	}
	if req.ExtendDays != nil && *req.ExtendDays != 0 {
		d := time.Duration(*req.ExtendDays) * 24 * time.Hour
		if lic.Status == models.StatusTrial && lic.TrialExpiresAt != nil {
			ne := lic.TrialExpiresAt.Add(d)
			set["trial_expires_at"] = ne
			h.history(id, "trial_expires_at", lic.TrialExpiresAt.Format(time.RFC3339), ne.Format(time.RFC3339), actor, req.Reason)
		} else {
			base := time.Now().UTC()
			if lic.ExpiresAt != nil && lic.ExpiresAt.After(base) {
				base = *lic.ExpiresAt
			}
			ne := base.Add(d)
			set["expires_at"] = ne
			h.history(id, "expires_at", "", ne.Format(time.RFC3339), actor, req.Reason)
		}
	}

	if _, err := h.Store.C("licenses").UpdateByID(ctx, id, bson.M{"$set": set}); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "update failed"})
		return
	}
	h.audit(actor, "update_license", lic.PublicID, req.Reason)

	var updated models.License
	h.Store.C("licenses").FindOne(ctx, bson.M{"_id": id}).Decode(&updated)
	c.JSON(http.StatusOK, gin.H{"license": updated})
}

/* ───────────── Rotate API key ───────────── */

func (h *Handler) RotateAPIKey(c *gin.Context) {
	id, err := primitive.ObjectIDFromHex(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "bad id"})
		return
	}
	ctx, cancel := reqCtx(c)
	defer cancel()

	apiKey, hash := services.NewAPIKey()
	res, err := h.Store.C("licenses").UpdateByID(ctx, id, bson.M{"$set": bson.M{"api_key_hash": hash, "updated_at": time.Now().UTC()}})
	if err != nil || res.MatchedCount == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "license not found"})
		return
	}
	actor := c.GetString("admin_email")
	h.history(id, "api_key", "(rotated)", "(rotated)", actor, "key rotation")
	h.audit(actor, "rotate_api_key", id.Hex(), "")
	c.JSON(http.StatusOK, gin.H{"api_key": apiKey}) // shown once
}

/* ───────────── Payments ───────────── */

func (h *Handler) RecordPayment(c *gin.Context) {
	var req struct {
		Amount       int    `json:"amount" binding:"required"`
		Currency     string `json:"currency"`
		Method       string `json:"method"`
		Reference    string `json:"reference"`
		CoversPeriod string `json:"covers_period"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	id, err := primitive.ObjectIDFromHex(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "bad id"})
		return
	}
	if req.Currency == "" {
		req.Currency = "INR"
	}
	ctx, cancel := reqCtx(c)
	defer cancel()

	p := models.Payment{
		LicenseID: id, Amount: req.Amount, Currency: req.Currency,
		Method: req.Method, Reference: req.Reference,
		PaidAt: time.Now().UTC(), CoversPeriod: req.CoversPeriod,
	}
	if _, err := h.Store.C("payments").InsertOne(ctx, p); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "payment insert failed"})
		return
	}
	h.Store.C("licenses").UpdateByID(ctx, id, bson.M{"$set": bson.M{"amount_paid": true, "updated_at": time.Now().UTC()}})
	actor := c.GetString("admin_email")
	h.history(id, "payment", "", fmt.Sprintf("%d %s (%s)", req.Amount, req.Currency, req.Method), actor, req.CoversPeriod)
	h.audit(actor, "record_payment", id.Hex(), fmt.Sprintf("%d %s", req.Amount, req.Currency))
	c.JSON(http.StatusCreated, gin.H{"payment": p})
}

/* ───────────── Quota requests ───────────── */

func (h *Handler) ListQuotaRequests(c *gin.Context) {
	ctx, cancel := reqCtx(c)
	defer cancel()

	filter := bson.M{}
	if s := c.Query("status"); s != "" {
		filter["status"] = s
	}
	cur, err := h.Store.C("quota_requests").Find(ctx, filter, options.Find().SetSort(bson.D{{Key: "requested_at", Value: -1}}).SetLimit(200))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "query failed"})
		return
	}
	var reqs []models.QuotaRequest
	cur.All(ctx, &reqs)

	type row struct {
		models.QuotaRequest
		Company  string `json:"company_name"`
		PublicID string `json:"license_public_id"`
		Quota    int    `json:"current_quota"`
	}
	out := make([]row, 0, len(reqs))
	for _, r := range reqs {
		var lic models.License
		h.Store.C("licenses").FindOne(ctx, bson.M{"_id": r.LicenseID}).Decode(&lic)
		var cust models.Customer
		h.Store.C("customers").FindOne(ctx, bson.M{"_id": lic.CustomerID}).Decode(&cust)
		out = append(out, row{QuotaRequest: r, Company: cust.CompanyName, PublicID: lic.PublicID, Quota: lic.MachineQuota})
	}
	c.JSON(http.StatusOK, gin.H{"requests": out})
}

func (h *Handler) DecideQuotaRequest(c *gin.Context) {
	var req struct {
		Approve bool   `json:"approve"`
		Note    string `json:"note"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	id, err := primitive.ObjectIDFromHex(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "bad id"})
		return
	}
	ctx, cancel := reqCtx(c)
	defer cancel()

	var qr models.QuotaRequest
	if err := h.Store.C("quota_requests").FindOne(ctx, bson.M{"_id": id}).Decode(&qr); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "request not found"})
		return
	}
	if qr.Status != "pending" {
		c.JSON(http.StatusConflict, gin.H{"error": "already decided"})
		return
	}

	var lic models.License
	if err := h.Store.C("licenses").FindOne(ctx, bson.M{"_id": qr.LicenseID}).Decode(&lic); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "license not found"})
		return
	}
	var cust models.Customer
	h.Store.C("customers").FindOne(ctx, bson.M{"_id": lic.CustomerID}).Decode(&cust)

	actor := c.GetString("admin_email")
	now := time.Now().UTC()
	newQuota := lic.MachineQuota

	if req.Approve {
		newQuota = lic.MachineQuota + qr.RequestedDelta
		plan := models.Plans[lic.Plan]
		if plan.MaxMachines > 0 && newQuota > plan.MaxMachines {
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("approving would exceed plan ceiling (%d) — upgrade the plan first", plan.MaxMachines)})
			return
		}
		h.Store.C("licenses").UpdateByID(ctx, lic.ID, bson.M{"$set": bson.M{"machine_quota": newQuota, "updated_at": now}})
		h.history(lic.ID, "machine_quota", strconv.Itoa(lic.MachineQuota), strconv.Itoa(newQuota), actor, "quota request approved")
	}

	status := "rejected"
	if req.Approve {
		status = "approved"
	}
	h.Store.C("quota_requests").UpdateByID(ctx, id, bson.M{"$set": bson.M{
		"status": status, "decided_at": now, "decided_by": actor, "note": req.Note,
	}})
	h.audit(actor, "decide_quota_request", lic.PublicID, status)

	subject, body := services.QuotaDecisionEmail(h.Cfg.PortalName, cust.CompanyName, req.Approve, qr.RequestedDelta, newQuota, req.Note)
	h.Mailer.SendAsync(cust.Email, subject, body)

	c.JSON(http.StatusOK, gin.H{"status": status, "new_quota": newQuota})
}

/* ───────────── SMTP config ───────────── */

func (h *Handler) GetSMTP(c *gin.Context) {
	ctx, cancel := reqCtx(c)
	defer cancel()
	var cfg models.SMTPConfig
	err := h.Store.C("smtp_config").FindOne(ctx, bson.M{"_id": "smtp"}).Decode(&cfg)
	if err != nil {
		// fall back to env values so the UI shows what's effective
		cfg = models.SMTPConfig{Host: h.Cfg.SMTPHost, Port: h.Cfg.SMTPPort, Username: h.Cfg.SMTPUser, From: h.Cfg.SMTPFrom}
	}
	if cfg.Password != "" {
		cfg.Password = "********"
	}
	c.JSON(http.StatusOK, gin.H{"smtp": cfg})
}

func (h *Handler) SaveSMTP(c *gin.Context) {
	var req models.SMTPConfig
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	ctx, cancel := reqCtx(c)
	defer cancel()

	// keep the stored password when the UI sends the mask back
	if req.Password == "" || req.Password == "********" {
		var existing models.SMTPConfig
		if err := h.Store.C("smtp_config").FindOne(ctx, bson.M{"_id": "smtp"}).Decode(&existing); err == nil {
			req.Password = existing.Password
		}
	}
	req.ID = "smtp"
	_, err := h.Store.C("smtp_config").ReplaceOne(ctx, bson.M{"_id": "smtp"}, req, options.Replace().SetUpsert(true))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "save failed"})
		return
	}
	h.audit(c.GetString("admin_email"), "save_smtp", req.Host, "")
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (h *Handler) TestSMTP(c *gin.Context) {
	var req struct {
		To string `json:"to" binding:"required,email"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	ctx, cancel := reqCtx(c)
	defer cancel()
	err := h.Mailer.Send(ctx, req.To, h.Cfg.PortalName+" — SMTP test", "<p>SMTP configuration is working. ✔</p>")
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

/* ───────────── Audit log ───────────── */

func (h *Handler) ListAudit(c *gin.Context) {
	ctx, cancel := reqCtx(c)
	defer cancel()
	cur, err := h.Store.C("audit_log").Find(ctx, bson.M{}, options.Find().SetSort(bson.D{{Key: "at", Value: -1}}).SetLimit(200))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "query failed"})
		return
	}
	var entries []models.AuditEntry
	cur.All(ctx, &entries)
	c.JSON(http.StatusOK, gin.H{"entries": entries})
}
