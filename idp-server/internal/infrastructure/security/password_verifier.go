package security

import (
	"errors"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

var ErrUnsupportedPasswordHash = errors.New("unsupported password hash")

type PasswordVerifier struct{}

func NewPasswordVerifier() *PasswordVerifier {
	return &PasswordVerifier{}
}

func (v *PasswordVerifier) HashPassword(password string) (string, error) {
	hashed, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashed), nil
}

func (v *PasswordVerifier) VerifyPassword(password, encodedHash string) error {
	if strings.TrimSpace(encodedHash) == "" {
		return ErrUnsupportedPasswordHash
	}

	// Dev helper: allow explicit plain-text fixtures without pretending they are hashed.
	if strings.HasPrefix(encodedHash, "plain:") {
		if password == strings.TrimPrefix(encodedHash, "plain:") {
			return nil
		}
		return bcrypt.ErrMismatchedHashAndPassword
	}

	return bcrypt.CompareHashAndPassword([]byte(encodedHash), []byte(password))
}
