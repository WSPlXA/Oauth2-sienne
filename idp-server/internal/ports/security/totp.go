package security

import "time"

type TOTPProvider interface {
	GenerateSecret() (string, error)
	ProvisioningURI(issuer, accountName, secret string) string
	VerifyCode(secret, code string, now time.Time) bool
	VerifyCodeWithStep(secret, code string, now time.Time) (bool, int64)
}
