package auth

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/smtp"
	"net/url"
	"strconv"
	"strings"
)

// VerificationMailer delivers one-time email verification links.
type VerificationMailer interface {
	SendVerification(to, token string) error
}

// SMTPConfig contains the SMTP connection and public verification URL.
type SMTPConfig struct {
	Host            string
	Port            int
	Username        string
	Password        string
	From            string
	VerificationURL string
	ImplicitTLS     bool
}

// SMTPMailer sends verification emails over mandatory TLS.
type SMTPMailer struct {
	cfg SMTPConfig
}

// NewSMTPMailer validates SMTP configuration and creates a mailer.
func NewSMTPMailer(cfg SMTPConfig) (*SMTPMailer, error) {
	if cfg.Host == "" || cfg.Port <= 0 || cfg.From == "" || cfg.VerificationURL == "" {
		return nil, fmt.Errorf("incomplete SMTP configuration")
	}
	verificationURL, err := url.Parse(cfg.VerificationURL)
	if err != nil || verificationURL.Scheme != "https" || verificationURL.Host == "" {
		return nil, fmt.Errorf("verification URL must be an absolute HTTPS URL")
	}
	return &SMTPMailer{cfg: cfg}, nil
}

// SendVerification sends a minimal plain-text message without logging secrets.
func (m *SMTPMailer) SendVerification(to, token string) error {
	verificationURL, err := url.Parse(m.cfg.VerificationURL)
	if err != nil {
		return fmt.Errorf("parsing verification URL: %w", err)
	}
	query := verificationURL.Query()
	query.Set("token", token)
	verificationURL.RawQuery = query.Encode()
	body := "Confirmez votre adresse email StageOps :\r\n\r\n" + verificationURL.String() +
		"\r\n\r\nCe lien est temporaire. Si vous n'êtes pas à l'origine de cette demande, ignorez cet email.\r\n"
	message := strings.Join([]string{
		"From: " + m.cfg.From,
		"To: " + to,
		"Subject: Confirmez votre compte StageOps",
		"MIME-Version: 1.0",
		"Content-Type: text/plain; charset=UTF-8",
		"",
		body,
	}, "\r\n")
	return m.send(to, strings.NewReader(message))
}

func (m *SMTPMailer) send(to string, message io.Reader) error {
	address := net.JoinHostPort(m.cfg.Host, strconv.Itoa(m.cfg.Port))
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: m.cfg.Host}
	var client *smtp.Client
	if m.cfg.ImplicitTLS {
		connection, err := tls.Dial("tcp", address, tlsConfig)
		if err != nil {
			return fmt.Errorf("connecting to SMTP over TLS: %w", err)
		}
		client, err = smtp.NewClient(connection, m.cfg.Host)
		if err != nil {
			_ = connection.Close()
			return fmt.Errorf("creating SMTP client: %w", err)
		}
	} else {
		var err error
		client, err = smtp.Dial(address)
		if err != nil {
			return fmt.Errorf("connecting to SMTP: %w", err)
		}
		if ok, _ := client.Extension("STARTTLS"); !ok {
			_ = client.Close()
			return fmt.Errorf("SMTP server does not support STARTTLS")
		}
		if err := client.StartTLS(tlsConfig); err != nil {
			_ = client.Close()
			return fmt.Errorf("starting SMTP TLS: %w", err)
		}
	}
	defer client.Close()
	if m.cfg.Username != "" {
		if err := client.Auth(smtp.PlainAuth("", m.cfg.Username, m.cfg.Password, m.cfg.Host)); err != nil {
			return fmt.Errorf("authenticating to SMTP: %w", err)
		}
	}
	if err := client.Mail(m.cfg.From); err != nil {
		return fmt.Errorf("setting SMTP sender: %w", err)
	}
	if err := client.Rcpt(to); err != nil {
		return fmt.Errorf("setting SMTP recipient: %w", err)
	}
	writer, err := client.Data()
	if err != nil {
		return fmt.Errorf("opening SMTP message: %w", err)
	}
	if _, err := io.Copy(writer, message); err != nil {
		_ = writer.Close()
		return fmt.Errorf("writing SMTP message: %w", err)
	}
	if err := writer.Close(); err != nil {
		return fmt.Errorf("closing SMTP message: %w", err)
	}
	if err := client.Quit(); err != nil {
		return fmt.Errorf("closing SMTP session: %w", err)
	}
	return nil
}
