package auth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewSMTPMailerRequiresHTTPSVerificationURL(t *testing.T) {
	_, err := NewSMTPMailer(SMTPConfig{
		Host: "smtp.example.com", Port: 587, From: "noreply@example.com",
		VerificationURL: "http://stageops.example.com/verify-email",
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "HTTPS")
}

func TestNewSMTPMailerAcceptsCompleteTLSConfiguration(t *testing.T) {
	mailer, err := NewSMTPMailer(SMTPConfig{
		Host: "smtp.example.com", Port: 587, From: "noreply@example.com",
		VerificationURL: "https://stageops.example.com/verify-email",
	})

	require.NoError(t, err)
	assert.NotNil(t, mailer)
	assert.Equal(t, defaultSMTPTimeout, mailer.cfg.Timeout)
}

func TestNewSMTPMailerRejectsHeaderInjectionInSender(t *testing.T) {
	_, err := NewSMTPMailer(SMTPConfig{
		Host: "smtp.example.com", Port: 587,
		From:            "noreply@example.com\r\nBcc: attacker@example.com",
		VerificationURL: "https://stageops.example.com/verify-email",
	})

	require.Error(t, err)
}

func TestSMTPMailerHonorsCanceledContext(t *testing.T) {
	mailer, err := NewSMTPMailer(SMTPConfig{
		Host: "127.0.0.1", Port: 1, From: "noreply@example.com",
		VerificationURL: "https://stageops.example.com/verify-email",
		Timeout:         time.Minute,
	})
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err = mailer.SendVerification(ctx, "user@example.com", "verification-token")

	require.Error(t, err)
	assert.True(t, errors.Is(err, context.Canceled), "expected context cancellation, got %v", err)
}
