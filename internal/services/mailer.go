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

func OnboardingEmail(portalName, company, email, password, apiKey, publicID, deploymentURL string, quota, trialDays int) (string, string) {
	subject := fmt.Sprintf("%s — your WebXTerm license & credentials", portalName)
	body := fmt.Sprintf(`
<div style="font-family:system-ui,sans-serif;max-width:560px;margin:0 auto;color:#0C1B2A">
  <h2 style="color:#155F9E">Welcome to WebXTerm, %s</h2>
  <p>Your license has been issued. Details below:</p>
  <table style="border-collapse:collapse;width:100%%;font-size:14px">
    <tr><td style="padding:6px 10px;color:#6B7C8C">License ID</td><td style="padding:6px 10px"><b>%s</b></td></tr>
    <tr><td style="padding:6px 10px;color:#6B7C8C">Machine quota</td><td style="padding:6px 10px"><b>%d machines</b></td></tr>
    <tr><td style="padding:6px 10px;color:#6B7C8C">Trial period</td><td style="padding:6px 10px"><b>%d days</b></td></tr>
  </table>
  <h3 style="color:#155F9E">Deployment superadmin login</h3>
  <p style="font-size:14px">Email: <b>%s</b><br/>Password: <code style="background:#EAF0F6;padding:2px 6px;border-radius:4px">%s</code></p>
  <h3 style="color:#155F9E">Deployment API key</h3>
  <p style="font-size:13px">Set this in your deployment environment as <code>LICENSE_API_KEY</code>:</p>
  <p><code style="background:#EAF0F6;padding:6px 10px;border-radius:6px;display:block;word-break:break-all">%s</code></p>
  <p style="font-size:13px;color:#6B7C8C">Deployment URL on record: %s<br/>
  This password is sent once and stored only as a hash — change it after first login.</p>
</div>`, company, publicID, quota, trialDays, email, password, apiKey, deploymentURL)
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
  <p>To keep creating machines, upgrade to a paid plan (Professional ₹499/machine/mo, Business ₹399/machine/mo, or Enterprise).</p>
</div>`, company, daysLeft)
	return subject, body
}
