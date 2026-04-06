package redis

import "testing"

func TestKeyBuilderTOTPStepUsed(t *testing.T) {
	builder := NewKeyBuilder("idp", "dev")
	got := builder.TOTPStepUsed("42", "login", 123456)
	want := "idp:dev:mfa:totp:used:42:login:123456"
	if got != want {
		t.Fatalf("TOTPStepUsed() = %q, want %q", got, want)
	}
}
