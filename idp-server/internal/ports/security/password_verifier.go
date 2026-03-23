package security

// PasswordVerifier defines password hashing and verification at the security boundary.
// Both end-user passwords and confidential client secrets can use the same contract.
type PasswordVerifier interface {
	HashPassword(password string) (string, error)
	VerifyPassword(password, encodedHash string) error
}
