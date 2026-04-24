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

func TestKeyBuilderSessionState(t *testing.T) {
	builder := NewKeyBuilder("idp", "dev")
	got := builder.SessionState("sid-1")
	want := "idp:dev:session:state:sid-1"
	if got != want {
		t.Fatalf("SessionState() = %q, want %q", got, want)
	}
}

func TestKeyBuilderMFAChallengeState(t *testing.T) {
	builder := NewKeyBuilder("idp", "dev")
	got := builder.MFAChallengeState("cid-1")
	want := "idp:dev:mfa:challenge:state:cid-1"
	if got != want {
		t.Fatalf("MFAChallengeState() = %q, want %q", got, want)
	}
}
