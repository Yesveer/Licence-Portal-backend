package services

import (
	"context"
	"fmt"
	"log"
	"net/smtp"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"

	"license-portal-backend/internal/config"
	"license-portal-backend/internal/db"
	"license-portal-backend/internal/models"
)

// Mailer sends portal emails (onboarding credentials, expiry reminders,
// quota approvals). SMTP config saved from the portal UI takes precedence;
// otherwise the SMTP_* env vars are used.
type Mailer struct {
	store *db.Store
	cfg   *config.Config
}

func NewMailer(store *db.Store, cfg *config.Config) *Mailer {
	return &Mailer{store: store, cfg: cfg}
}

func (m *Mailer) resolveConfig(ctx context.Context) (models.SMTPConfig, error) {
	var c models.SMTPConfig
	err := m.store.C("smtp_config").FindOne(ctx, bson.M{"_id": "smtp"}).Decode(&c)
	if err == nil && c.Host != "" {
		return c, nil
	}
	if err != nil && err != mongo.ErrNoDocuments {
		return c, err
	}
	if m.cfg.SMTPHost == "" {
		return c, fmt.Errorf("smtp not configured (set it in portal settings or SMTP_* env vars)")
	}
	return models.SMTPConfig{
		Host: m.cfg.SMTPHost, Port: m.cfg.SMTPPort,
		Username: m.cfg.SMTPUser, Password: m.cfg.SMTPPass, From: m.cfg.SMTPFrom,
	}, nil
}

func (m *Mailer) Send(ctx context.Context, to, subject, htmlBody string) error {
	c, err := m.resolveConfig(ctx)
	if err != nil {
		return err
	}
	from := c.From
	if from == "" {
		from = m.cfg.SMTPFrom
	}

	msg := strings.Join([]string{
		"From: " + from,
		"To: " + to,
		"Subject: " + subject,
		"MIME-Version: 1.0",
		"Content-Type: text/html; charset=\"UTF-8\"",
		"",
		htmlBody,
	}, "\r\n")

	addr := fmt.Sprintf("%s:%d", c.Host, c.Port)
	var auth smtp.Auth
	if c.Username != "" {
		auth = smtp.PlainAuth("", c.Username, c.Password, c.Host)
	}
	if err := smtp.SendMail(addr, auth, from, []string{to}, []byte(msg)); err != nil {
		return fmt.Errorf("smtp send failed: %w", err)
	}
	return nil
}

// SendAsync fires the mail in a goroutine — onboarding must not fail just
// because SMTP is down; the credentials remain visible in the API response.
func (m *Mailer) SendAsync(to, subject, htmlBody string) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := m.Send(ctx, to, subject, htmlBody); err != nil {
			log.Printf("mailer: send to %s failed: %v", to, err)
		} else {
			log.Printf("mailer: sent %q to %s", subject, to)
		}
	}()
}

/* ───────────── Templates ───────────── */

func OnboardingEmail(portalName, company, email, password, apiKey, publicID, deploymentURL, planName string, isTrial bool, quota, trialDays int, subscribedAt time.Time) (string, string) {
	subject := fmt.Sprintf("%s — your WebXTerm license & credentials", portalName)

	// password is "" when this customer already has an account (onboarding
	// a second product) — same login, so skip the credentials block.
	loginSection := ""
	if password != "" {
		loginSection = fmt.Sprintf(`
  <h3 style="color:#155F9E">Deployment superadmin login</h3>
  <p style="font-size:14px">Email: <b>%s</b><br/>Password: <code style="background:#EAF0F6;padding:2px 6px;border-radius:4px">%s</code></p>
  <p style="font-size:13px;color:#6B7C8C">This password is sent once and stored only as a hash — change it after first login.</p>`, email, password)
	} else {
		loginSection = `
  <p style="font-size:13px;color:#6B7C8C">Use your existing WebXTerm login for this new license — no new password was issued.</p>`
	}

	// only a trial plan actually has a trial period — a paid plan has none.
	trialRow := ""
	if isTrial {
		trialRow = fmt.Sprintf(`<tr><td style="padding:6px 10px;color:#6B7C8C">Trial period</td><td style="padding:6px 10px"><b>%d days</b></td></tr>`, trialDays)
	}

	body := fmt.Sprintf(`
<div style="font-family:system-ui,sans-serif;max-width:560px;margin:0 auto;color:#0C1B2A">
  <h2 style="color:#155F9E">Welcome to WebXTerm, %s</h2>
  <p>You have subscribed for the <b>%s</b> plan, with a max machine quota to manage of <b>%d</b>.</p>
  <table style="border-collapse:collapse;width:100%%;font-size:14px">
    <tr><td style="padding:6px 10px;color:#6B7C8C">License ID</td><td style="padding:6px 10px"><b>%s</b></td></tr>
    <tr><td style="padding:6px 10px;color:#6B7C8C">Plan</td><td style="padding:6px 10px"><b>%s</b></td></tr>
    <tr><td style="padding:6px 10px;color:#6B7C8C">Machine quota</td><td style="padding:6px 10px"><b>%d machines</b></td></tr>
    <tr><td style="padding:6px 10px;color:#6B7C8C">Subscribed on</td><td style="padding:6px 10px"><b>%s</b></td></tr>
    %s
  </table>%s
  <h3 style="color:#155F9E">Deployment API key</h3>
  <p style="font-size:13px">Set this in your deployment environment as <code>LICENSE_API_KEY</code>:</p>
  <p><code style="background:#EAF0F6;padding:6px 10px;border-radius:6px;display:block;word-break:break-all">%s</code></p>
  <p style="font-size:13px;color:#6B7C8C">Deployment URL on record: %s</p>
</div>`, company, planName, quota, publicID, planName, quota, subscribedAt.Format("02 Jan 2006"), trialRow, loginSection, apiKey, deploymentURL)
	return subject, body
}

// UpgradeEmail is sent when an existing license changes plan tier. The login
// (email + password) never changes here, and the password itself is never
// re-shown — only its bcrypt hash is ever stored, even to us.
func UpgradeEmail(portalName, company, email, oldPlan, newPlan, apiKey, publicID string, quota int, upgradedAt time.Time) (string, string) {
	subject := fmt.Sprintf("%s — your license has been upgraded", portalName)
	body := fmt.Sprintf(`
<div style="font-family:system-ui,sans-serif;max-width:560px;margin:0 auto;color:#0C1B2A">
  <h2 style="color:#155F9E">Your WebXTerm license has been upgraded, %s</h2>
  <p>Your plan changed from <b>%s</b> to <b>%s</b>, with a new max machine quota to manage of <b>%d</b>.</p>
  <table style="border-collapse:collapse;width:100%%;font-size:14px">
    <tr><td style="padding:6px 10px;color:#6B7C8C">License ID</td><td style="padding:6px 10px"><b>%s</b></td></tr>
    <tr><td style="padding:6px 10px;color:#6B7C8C">New plan</td><td style="padding:6px 10px"><b>%s</b></td></tr>
    <tr><td style="padding:6px 10px;color:#6B7C8C">Machine quota</td><td style="padding:6px 10px"><b>%d machines</b></td></tr>
    <tr><td style="padding:6px 10px;color:#6B7C8C">Upgraded on</td><td style="padding:6px 10px"><b>%s</b></td></tr>
  </table>
  <p style="font-size:13px;color:#6B7C8C">Your login (<b>%s</b>) and existing password are unchanged — no new credentials were issued.</p>
  <h3 style="color:#155F9E">New deployment API key</h3>
  <p style="font-size:13px">Your previous key stops working immediately. Set this in your deployment environment as <code>LICENSE_API_KEY</code>:</p>
  <p><code style="background:#EAF0F6;padding:6px 10px;border-radius:6px;display:block;word-break:break-all">%s</code></p>
</div>`, company, oldPlan, newPlan, quota, publicID, newPlan, quota, upgradedAt.Format("02 Jan 2006"), email, apiKey)
	return subject, body
}

// KeyRotatedEmail is sent every time the deployment API key changes for any
// reason — a manual "Rotate API key", or a plan upgrade/demotion. The old key
// stops working the instant this happens, so the new one must always reach
// the customer.
func KeyRotatedEmail(portalName, company, publicID, apiKey string, rotatedAt time.Time) (string, string) {
	subject := fmt.Sprintf("%s — your deployment API key was rotated", portalName)
	body := fmt.Sprintf(`
<div style="font-family:system-ui,sans-serif;max-width:560px;margin:0 auto;color:#0C1B2A">
  <h2 style="color:#155F9E">Your deployment API key has been rotated</h2>
  <p>Hi %s, the deployment API key for license <b>%s</b> was rotated on <b>%s</b>. Your previous key stopped working immediately.</p>
  <h3 style="color:#155F9E">New deployment API key</h3>
  <p style="font-size:13px">Set this in your deployment environment as <code>LICENSE_API_KEY</code>:</p>
  <p><code style="background:#EAF0F6;padding:6px 10px;border-radius:6px;display:block;word-break:break-all">%s</code></p>
</div>`, company, publicID, rotatedAt.Format("02 Jan 2006"), apiKey)
	return subject, body
}

// LicenseUpdateEmail is sent for in-place changes (machine quota, extended
// validity) that never touch the API key or login — so it never includes
// either.
func LicenseUpdateEmail(portalName, company, publicID, summary string, updatedAt time.Time) (string, string) {
	subject := fmt.Sprintf("%s — your license was updated", portalName)
	body := fmt.Sprintf(`
<div style="font-family:system-ui,sans-serif;max-width:560px;margin:0 auto;color:#0C1B2A">
  <h2 style="color:#155F9E">Your license has been updated</h2>
  <p>Hi %s, license <b>%s</b> was updated on <b>%s</b>:</p>
  <p style="font-size:14px"><b>%s</b></p>
  <p style="font-size:13px;color:#6B7C8C">No new credentials or API key were issued — your deployment key and login are unchanged.</p>
</div>`, company, publicID, updatedAt.Format("02 Jan 2006"), summary)
	return subject, body
}

func QuotaDecisionEmail(portalName, company string, approved bool, delta, newQuota int, note string) (string, string) {
	verdict, color := "approved", "#1E7A4C"
	if !approved {
		verdict, color = "rejected", "#B0353A"
	}
	subject := fmt.Sprintf("%s — quota request %s", portalName, verdict)
	body := fmt.Sprintf(`
<div style="font-family:system-ui,sans-serif;max-width:560px;margin:0 auto;color:#0C1B2A">
  <h2 style="color:%s">Quota request %s</h2>
  <p>Hi %s, your request for <b>+%d machines</b> has been <b>%s</b>.</p>
  <p>Current machine quota: <b>%d</b>.</p>
  <p style="font-size:13px;color:#6B7C8C">%s</p>
  <p style="font-size:13px;color:#6B7C8C">Your deployment will pick up the new quota on its next license refresh.</p>
</div>`, color, verdict, company, delta, verdict, newQuota, note)
	return subject, body
}

func ExpiryReminderEmail(portalName, company string, daysLeft int) (string, string) {
	subject := fmt.Sprintf("%s — your trial expires in %d day(s)", portalName, daysLeft)
	body := fmt.Sprintf(`
<div style="font-family:system-ui,sans-serif;max-width:560px;margin:0 auto;color:#0C1B2A">
  <h2 style="color:#B5770D">Trial expiring soon</h2>
  <p>Hi %s, your WebXTerm trial expires in <b>%d day(s)</b>.</p>
  <p>To keep creating machines, upgrade to a paid plan (Professional or Enterprise).</p>
</div>`, company, daysLeft)
	return subject, body
}
