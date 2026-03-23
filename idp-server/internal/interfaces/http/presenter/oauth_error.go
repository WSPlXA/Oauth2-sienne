package presenter

import "idp-server/pkg/oauth2"

func OAuthError(code, description string) oauth2.Error {
	return oauth2.Error{
		Code:        code,
		Description: description,
	}
}
