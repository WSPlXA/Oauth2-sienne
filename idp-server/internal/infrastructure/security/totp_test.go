package security

import (
	"encoding/base32"
	"strings"
	"testing"
	"time"
)

func TestTOTPProviderVerifyCodeWithStepMatchesWindow(t *testing.T) {
	provider := NewTOTPProvider()
	secret := "JBSWY3DPEHPK3PXP"
	key := mustDecodeBase32NoPadding(t, secret)
	now := time.Unix(1712345678, 0).UTC()
	currentStep := now.Unix() / provider.period

	tests := []struct {
		name string
		step int64
	}{
		{name: "previous", step: currentStep - 1},
		{name: "current", step: currentStep},
		{name: "next", step: currentStep + 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code := provider.generateCode(key, tt.step)
			ok, matchedStep := provider.VerifyCodeWithStep(secret, code, now)
			if !ok {
				t.Fatalf("VerifyCodeWithStep() ok = false, want true")
			}
			if matchedStep != tt.step {
				t.Fatalf("VerifyCodeWithStep() step = %d, want %d", matchedStep, tt.step)
			}
		})
	}
}

func TestTOTPProviderVerifyCodeWithStepRejectsOutsideWindow(t *testing.T) {
	provider := NewTOTPProvider()
	secret := "JBSWY3DPEHPK3PXP"
	key := mustDecodeBase32NoPadding(t, secret)
	now := time.Unix(1712345678, 0).UTC()
	currentStep := now.Unix() / provider.period
	code := provider.generateCode(key, currentStep-2)

	ok, matchedStep := provider.VerifyCodeWithStep(secret, code, now)
	if ok {
		t.Fatalf("VerifyCodeWithStep() ok = true, want false")
	}
	if matchedStep != 0 {
		t.Fatalf("VerifyCodeWithStep() step = %d, want 0", matchedStep)
	}
}

func mustDecodeBase32NoPadding(t *testing.T, secret string) []byte {
	t.Helper()

	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil {
		t.Fatalf("DecodeString() error = %v", err)
	}
	return key
}
