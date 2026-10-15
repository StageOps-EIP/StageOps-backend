package auth

import (
	"testing"

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
}
