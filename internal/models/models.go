package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// PAM and EPM share this backend/database; only License is product-scoped.
const (
	ProductPAM = "pam"
	ProductEPM = "epm"
)

func ValidProduct(p string) bool {
	return p == ProductPAM || p == ProductEPM
}

// NormalizeProduct treats "" as ProductPAM, for licenses created before this field existed.
func NormalizeProduct(p string) string {
	if p == "" {
		return ProductPAM
	}
	return p
}

/* ───────────── Plans (from webxterm.me/pricing) ───────────── */
// Per-product — three tiers each: Community, Professional, Enterprise.

type Plan struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	RatePerMachine int    `json:"rate_per_machine"` // ₹ / machine / month (0 = free or custom)
	MaxMachines    int    `json:"max_machines"`     // -1 = unlimited (Enterprise)
	Trial          bool   `json:"trial"`
	Description    string `json:"description"`
}

// PAM Enterprise is priced per number of machines, negotiated per customer —
// see License.CustomRate, set by the admin at onboarding/renewal time.
var pamPlans = map[string]Plan{
	"community":    {ID: "community", Name: "Community", RatePerMachine: 0, MaxMachines: 10, Trial: true, Description: "Free for 30 days · up to 10 machines"},
	"professional": {ID: "professional", Name: "Professional", RatePerMachine: 499, MaxMachines: 100, Description: "₹499 / machine / month · up to 100 machines"},
	"enterprise":   {ID: "enterprise", Name: "Enterprise", RatePerMachine: 0, MaxMachines: -1, Description: "Custom quote · unlimited machines"},
}

// EPM Enterprise has a fixed per-machine rate rather than a custom quote.
var epmPlans = map[string]Plan{
	"community":    {ID: "community", Name: "Community", RatePerMachine: 0, MaxMachines: 10, Trial: true, Description: "Free for 30 days · up to 10 machines"},
	"professional": {ID: "professional", Name: "Professional", RatePerMachine: 659, MaxMachines: 100, Description: "₹659 / machine / month · up to 100 machines"},
	"enterprise":   {ID: "enterprise", Name: "Enterprise", RatePerMachine: 499, MaxMachines: -1, Description: "₹499 / machine / month · unlimited machines"},
}

var plansByProduct = map[string]map[string]Plan{
	ProductPAM: pamPlans,
	ProductEPM: epmPlans,
}

// planOrder is the stable display order for the UI.
var planOrder = []string{"community", "professional", "enterprise"}

func ProductPlans(product string) map[string]Plan {
	if p, ok := plansByProduct[NormalizeProduct(product)]; ok {
		return p
	}
	return pamPlans
}

func ProductPlanOrder(product string) []string {
	return planOrder
}

/* ───────────── License status state machine ───────────── */

const (
	StatusTrial     = "trial"
	StatusConfirmed = "confirmed"
	StatusSuspended = "suspended"
	StatusExpired   = "expired"
	StatusRevoked   = "revoked"
)

/* ───────────── Entities ───────────── */

/* ───────────── Portal user roles ─────────────
   superadmin — full access (SMTP, audit log, user management included)
   admin      — team member: everything except SMTP, audit log & user management */

const (
	RoleSuperadmin = "superadmin"
	RoleAdmin      = "admin"
)

type AdminUser struct {
	ID           primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	Email        string             `bson:"email" json:"email"`
	PasswordHash string             `bson:"password_hash" json:"-"`
	Role         string             `bson:"role" json:"role"`
	CreatedBy    string             `bson:"created_by,omitempty" json:"created_by,omitempty"`
	CreatedAt    time.Time          `bson:"created_at" json:"created_at"`
}

// Customer is matched by email across onboardings — one company with both
// a PAM and an EPM license is ONE Customer document with Products holding
// both, not two separate rows.
type Customer struct {
	ID          primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	Products    []string           `bson:"products" json:"products"`
	CompanyName string             `bson:"company_name" json:"company_name"`
	Email       string             `bson:"email" json:"email"`
	Phone       string             `bson:"phone" json:"phone"`
	CreatedAt   time.Time          `bson:"created_at" json:"created_at"`
}

type License struct {
	ID             primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	CustomerID     primitive.ObjectID `bson:"customer_id" json:"customer_id"`
	Product        string             `bson:"product" json:"product"`     // "pam" or "epm" — see ProductPAM/ProductEPM. Never changes after creation.
	PublicID       string             `bson:"public_id" json:"public_id"` // e.g. LIC-XXXXXXXX (pam) or EPM-XXXXXXXX (epm)
	Plan           string             `bson:"plan" json:"plan"`
	MachineQuota   int                `bson:"machine_quota" json:"machine_quota"`
	CustomRate     int                `bson:"custom_rate,omitempty" json:"custom_rate,omitempty"` // Enterprise negotiated ₹/machine/mo
	Status         string             `bson:"status" json:"status"`
	UpdatesGranted bool               `bson:"updates_granted" json:"updates_granted"`
	UpdateChannel  string             `bson:"update_channel" json:"update_channel"` // allowed version, e.g. "1.4.x"
	DeploymentURL  string             `bson:"deployment_url" json:"deployment_url"`
	// Exposed to the admin portal only (never to deployment-facing /api/v1/*,
	// which builds its own response fields rather than marshaling this struct)
	// so support can compare a customer-supplied key's hash without ever
	// storing or re-showing the plaintext key.
	APIKeyHash string `bson:"api_key_hash" json:"api_key_hash"`
	// PrevAPIKeyHash keeps the just-rotated-out key valid until PrevAPIKeyExpiresAt
	// — an overlap window so an admin has time to update LICENSE_API_KEY on
	// the deployment before the old one stops working. See config.KeyRotationGrace.
	PrevAPIKeyHash      string     `bson:"prev_api_key_hash,omitempty" json:"-"`
	PrevAPIKeyExpiresAt *time.Time `bson:"prev_api_key_expires_at,omitempty" json:"prev_api_key_expires_at,omitempty"`
	TrialExpiresAt *time.Time         `bson:"trial_expires_at,omitempty" json:"trial_expires_at,omitempty"`
	ExpiresAt      *time.Time         `bson:"expires_at,omitempty" json:"expires_at,omitempty"` // paid-license expiry (renewal)
	ActivatedAt    *time.Time         `bson:"activated_at,omitempty" json:"activated_at,omitempty"`
	LastSeenAt     *time.Time         `bson:"last_seen_at,omitempty" json:"last_seen_at,omitempty"`
	ProductVersion string             `bson:"product_version,omitempty" json:"product_version,omitempty"`
	AmountPaid     bool               `bson:"amount_paid" json:"amount_paid"`
	CreatedAt      time.Time          `bson:"created_at" json:"created_at"`
	UpdatedAt      time.Time          `bson:"updated_at" json:"updated_at"`
}

// EffectiveExpiry returns the date after which the license is no longer valid.
func (l *License) EffectiveExpiry() *time.Time {
	if l.Status == StatusTrial {
		return l.TrialExpiresAt
	}
	return l.ExpiresAt
}

// GetProduct normalizes the stored Product — see NormalizeProduct.
func (l *License) GetProduct() string {
	return NormalizeProduct(l.Product)
}

type Machine struct {
	ID            primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	LicenseID     primitive.ObjectID `bson:"license_id" json:"license_id"`
	Product       string             `bson:"product" json:"product"` // copied from the owning license
	Fingerprint   string             `bson:"fingerprint" json:"fingerprint"`
	Name          string             `bson:"name,omitempty" json:"name,omitempty"`
	TenantRef     string             `bson:"tenant_ref,omitempty" json:"tenant_ref,omitempty"`
	Active        bool               `bson:"active" json:"active"`
	FirstSeen     time.Time          `bson:"first_seen" json:"first_seen"`
	LastHeartbeat time.Time          `bson:"last_heartbeat" json:"last_heartbeat"`
}

type QuotaRequest struct {
	ID             primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	LicenseID      primitive.ObjectID `bson:"license_id" json:"license_id"`
	Product        string             `bson:"product" json:"product"` // copied from the owning license
	RequestedDelta int                `bson:"requested_delta" json:"requested_delta"`
	Reason         string             `bson:"reason,omitempty" json:"reason,omitempty"`
	Status         string             `bson:"status" json:"status"` // pending · approved · rejected
	RequestedAt    time.Time          `bson:"requested_at" json:"requested_at"`
	DecidedAt      *time.Time         `bson:"decided_at,omitempty" json:"decided_at,omitempty"`
	DecidedBy      string             `bson:"decided_by,omitempty" json:"decided_by,omitempty"`
	Note           string             `bson:"note,omitempty" json:"note,omitempty"`
}

type LicenseHistory struct {
	ID        primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	LicenseID primitive.ObjectID `bson:"license_id" json:"license_id"`
	Product   string             `bson:"product" json:"product"` // copied from the owning license
	Field     string             `bson:"field" json:"field"`
	OldValue  string             `bson:"old_value" json:"old_value"`
	NewValue  string             `bson:"new_value" json:"new_value"`
	Actor     string             `bson:"actor" json:"actor"`
	Reason    string             `bson:"reason,omitempty" json:"reason,omitempty"`
	ChangedAt time.Time          `bson:"changed_at" json:"changed_at"`
}

type Payment struct {
	ID           primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	LicenseID    primitive.ObjectID `bson:"license_id" json:"license_id"`
	Product      string             `bson:"product" json:"product"` // copied from the owning license
	Amount       int                `bson:"amount" json:"amount"`
	Currency     string             `bson:"currency" json:"currency"`
	Method       string             `bson:"method" json:"method"`
	Reference    string             `bson:"reference,omitempty" json:"reference,omitempty"`
	PaidAt       time.Time          `bson:"paid_at" json:"paid_at"`
	CoversPeriod string             `bson:"covers_period,omitempty" json:"covers_period,omitempty"`
}

type AuditEntry struct {
	ID       primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	Actor    string             `bson:"actor" json:"actor"`
	Action   string             `bson:"action" json:"action"`
	Target   string             `bson:"target" json:"target"`
	Metadata string             `bson:"metadata,omitempty" json:"metadata,omitempty"`
	At       time.Time          `bson:"at" json:"at"`
}

type SMTPConfig struct {
	ID       string `bson:"_id" json:"-"` // singleton: "smtp"
	Host     string `bson:"host" json:"host"`
	Port     int    `bson:"port" json:"port"`
	Username string `bson:"username" json:"username"`
	Password string `bson:"password" json:"password"` // returned masked by the API
	From     string `bson:"from" json:"from"`
}

type SigningKeys struct {
	ID         string    `bson:"_id" json:"-"` // singleton: "ed25519"
	PrivateB64 string    `bson:"private_b64" json:"-"`
	PublicB64  string    `bson:"public_b64" json:"public_b64"`
	CreatedAt  time.Time `bson:"created_at" json:"created_at"`
}
