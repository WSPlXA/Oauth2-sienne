package security

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

type TOTPProvider struct {
	period int64
	digits int
	skew   int64
}

func NewTOTPProvider() *TOTPProvider {
	return &TOTPProvider{
		period: 30,
		digits: 6,
		skew:   1,
	}
}

func (p *TOTPProvider) GenerateSecret() (string, error) {
	raw := make([]byte, 20)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return strings.TrimRight(base32.StdEncoding.EncodeToString(raw), "="), nil
}

func (p *TOTPProvider) ProvisioningURI(issuer, accountName, secret string) string {
	issuer = strings.TrimSpace(issuer)
	accountName = strings.TrimSpace(accountName)
	label := url.PathEscape(accountName)
	if issuer != "" {
		label = url.PathEscape(issuer + ":" + accountName)
	}
	values := url.Values{}
	values.Set("secret", secret)
	if issuer != "" {
		values.Set("issuer", issuer)
	}
	values.Set("algorithm", "SHA1")
	values.Set("digits", fmt.Sprintf("%d", p.digits))
	values.Set("period", fmt.Sprintf("%d", p.period))
	return "otpauth://totp/" + label + "?" + values.Encode()
}

func (p *TOTPProvider) VerifyCode(secret, code string, now time.Time) bool {
	ok, _ := p.VerifyCodeWithStep(secret, code, now)
	return ok
}

func (p *TOTPProvider) VerifyCodeWithStep(secret, code string, now time.Time) (bool, int64) {
	code = strings.TrimSpace(code)
	if len(code) != p.digits {
		return false, 0
	}
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil || len(key) == 0 {
		return false, 0
	}
	counter := now.UTC().Unix() / p.period
	for offset := -p.skew; offset <= p.skew; offset++ {
		step := counter + offset
		if p.generateCode(key, step) == code {
			return true, step
		}
	}
	return false, 0
}

func (p *TOTPProvider) generateCode(key []byte, counter int64) string {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(counter))
	mac := hmac.New(sha1.New, key)
	_, _ = mac.Write(buf[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	truncated := int(binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff)
	modulo := 1
	for i := 0; i < p.digits; i++ {
		modulo *= 10
	}
	return fmt.Sprintf("%0*d", p.digits, truncated%modulo)
}
