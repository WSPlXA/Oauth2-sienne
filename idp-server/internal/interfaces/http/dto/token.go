package dto

import (
	"fmt"
	"strings"

	pkgoauth2 "idp-server/pkg/oauth2"
)

type TokenRequest struct {
	GrantType    string `form:"grant_type" json:"grant_type" binding:"required"`
	Code         string `form:"code" json:"code"`
	RedirectURI  string `form:"redirect_uri" json:"redirect_uri"`
	RefreshToken string `form:"refresh_token" json:"refresh_token"`
	DeviceCode   string `form:"device_code" json:"device_code"`
	ClientID     string `form:"client_id" json:"client_id"`
	ClientSecret string `form:"client_secret" json:"client_secret"`
	CodeVerifier string `form:"code_verifier" json:"code_verifier"`
	Username     string `form:"username" json:"username"`
	Password     string `form:"password" json:"password"`
	Scope        string `form:"scope" json:"scope"`
}

func (r TokenRequest) Validate() error {
	switch pkgoauth2.GrantType(r.GrantType) {
	case pkgoauth2.GrantTypeAuthorizationCode:
		if strings.TrimSpace(r.Code) == "" {
			return fmt.Errorf("code is required for authorization_code")
		}
		if strings.TrimSpace(r.RedirectURI) == "" {
			return fmt.Errorf("redirect_uri is required for authorization_code")
		}
	case pkgoauth2.GrantTypeRefreshToken:
		if strings.TrimSpace(r.RefreshToken) == "" {
			return fmt.Errorf("refresh_token is required for refresh_token")
		}
	case pkgoauth2.GrantTypeClientCredentials:
		return nil
	case pkgoauth2.GrantTypePassword:
		if strings.TrimSpace(r.Username) == "" {
			return fmt.Errorf("username is required for password")
		}
		if r.Password == "" {
			return fmt.Errorf("password is required for password")
		}
	case pkgoauth2.GrantTypeDeviceCode:
		if strings.TrimSpace(r.DeviceCode) == "" {
			return fmt.Errorf("device_code is required for device_code")
		}
	default:
		return fmt.Errorf("unsupported grant_type: %s", r.GrantType)
	}

	return nil
}

func (r TokenRequest) ScopeList() []string {
	if strings.TrimSpace(r.Scope) == "" {
		return nil
	}
	return strings.Fields(r.Scope)
}
