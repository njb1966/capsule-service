package email

import (
	"fmt"
	"net/smtp"
	"strings"

	"gemcities.com/capsule-service/config"
)

type Sender struct {
	cfg config.EmailConfig
}

func New(cfg config.EmailConfig) *Sender {
	return &Sender{cfg: cfg}
}

func (s *Sender) Send(to, subject, body string) error {
	addr := fmt.Sprintf("%s:%d", s.cfg.SMTPHost, s.cfg.SMTPPort)
	auth := smtp.PlainAuth("", s.cfg.SMTPUsername, s.cfg.SMTPPassword, s.cfg.SMTPHost)

	msg := strings.Join([]string{
		fmt.Sprintf("From: %s", s.cfg.FromAddress),
		fmt.Sprintf("To: %s", to),
		fmt.Sprintf("Subject: %s", subject),
		"MIME-Version: 1.0",
		"Content-Type: text/plain; charset=utf-8",
		"",
		body,
	}, "\r\n")

	return smtp.SendMail(addr, auth, s.cfg.FromAddress, []string{to}, []byte(msg))
}

func (s *Sender) SendVerification(to, username, token string, domain string) error {
	link := fmt.Sprintf("https://%s/verify-email.html?token=%s", domain, token)
	body := fmt.Sprintf("Hi %s,\n\nVerify your gemcities.com account:\n\n%s\n\nThis link expires in 24 hours.\n\nIf you did not register, ignore this email.\n", username, link)
	return s.Send(to, "Verify your gemcities.com account", body)
}

func (s *Sender) SendPasswordReset(to, token string, domain string) error {
	link := fmt.Sprintf("https://%s/reset-password.html?token=%s", domain, token)
	body := fmt.Sprintf("A password reset was requested for this email address.\n\nReset your password:\n\n%s\n\nThis link expires in 1 hour.\n\nIf you did not request this, ignore this email.\n", link)
	return s.Send(to, "Reset your gemcities.com password", body)
}
