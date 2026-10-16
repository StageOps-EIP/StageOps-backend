package auth

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/mail"
	"net/smtp"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const defaultSMTPTimeout = 10 * time.Second

// VerificationMailer delivers one-time email verification links.
type VerificationMailer interface {
	SendVerification(ctx context.Context, to, token string) error
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
	Timeout         time.Duration
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
	if strings.ContainsAny(cfg.Host+cfg.From+cfg.Username, "\r\n") {
		return nil, fmt.Errorf("SMTP configuration contains forbidden newline characters")
	}
	fromAddress, err := mail.ParseAddress(cfg.From)
	if err != nil || fromAddress.Address != cfg.From {
		return nil, fmt.Errorf("SMTP sender must be a plain email address")
	}
	verificationURL, err := url.Parse(cfg.VerificationURL)
	if err != nil || verificationURL.Scheme != "https" || verificationURL.Host == "" {
		return nil, fmt.Errorf("verification URL must be an absolute HTTPS URL")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = defaultSMTPTimeout
	}
	return &SMTPMailer{cfg: cfg}, nil
}

// SendVerification sends a minimal plain-text message without logging secrets.
func (m *SMTPMailer) SendVerification(ctx context.Context, to, token string) error {
	verificationURL, err := url.Parse(m.cfg.VerificationURL)
	if err != nil {
		return fmt.Errorf("parsing verification URL: %w", err)
	}
	verificationURL.Fragment = "token=" + url.QueryEscape(token)
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
	return m.send(ctx, to, strings.NewReader(message))
}

func (m *SMTPMailer) send(ctx context.Context, to string, message io.Reader) error {
	address := net.JoinHostPort(m.cfg.Host, strconv.Itoa(m.cfg.Port))
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: m.cfg.Host}
	dialer := &net.Dialer{Timeout: m.cfg.Timeout}
	connection, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return fmt.Errorf("connecting to SMTP: %w", err)
	}
	deadline := time.Now().Add(m.cfg.Timeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err := connection.SetDeadline(deadline); err != nil {
		_ = connection.Close()
		return fmt.Errorf("setting SMTP connection deadline: %w", err)
	}

	var client *smtp.Client
	if m.cfg.ImplicitTLS {
		tlsConnection := tls.Client(connection, tlsConfig)
		if err := tlsConnection.HandshakeContext(ctx); err != nil {
			_ = connection.Close()
			return fmt.Errorf("starting implicit SMTP TLS: %w", err)
		}
		client, err = smtp.NewClient(tlsConnection, m.cfg.Host)
		if err != nil {
			_ = connection.Close()
			return fmt.Errorf("creating SMTP client: %w", err)
		}
	} else {
		client, err = smtp.NewClient(connection, m.cfg.Host)
		if err != nil {
			_ = connection.Close()
			return fmt.Errorf("creating SMTP client: %w", err)
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
