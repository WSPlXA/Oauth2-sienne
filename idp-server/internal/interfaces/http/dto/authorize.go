package dto

import "strings"

type AuthorizeRequest struct {
	ResponseType        string `form:"response_type" json:"response_type" binding:"required"`
	ClientID            string `form:"client_id" json:"client_id" binding:"required"`
	RedirectURI         string `form:"redirect_uri" json:"redirect_uri" binding:"required"`
	Scope               string `form:"scope" json:"scope"`
	State               string `form:"state" json:"state"`
	Nonce               string `form:"nonce" json:"nonce"`
	CodeChallenge       string `form:"code_challenge" json:"code_challenge"`
	CodeChallengeMethod string `form:"code_challenge_method" json:"code_challenge_method"`
}

func (r AuthorizeRequest) ScopeList() []string {
	if strings.TrimSpace(r.Scope) == "" {
		return nil
	}
	return strings.Fields(r.Scope)
}
