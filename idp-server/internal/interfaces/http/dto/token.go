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
	ClientID     string `form:"client_id" json:"client_id"`
	ClientSecret string `form:"client_secret" json:"client_secret"`
	CodeVerifier string `form:"code_verifier" json:"code_verifier"`
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
