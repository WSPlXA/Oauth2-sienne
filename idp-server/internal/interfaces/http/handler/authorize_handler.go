package handler

import (
	"errors"
	"idp-server/internal/application/authz"
	appauthz "idp-server/internal/application/authz"
	"idp-server/internal/interfaces/http/dto"
	"net/http"
	"net/url"
	pkgoauth2 "idp-server/pkg/oauth2"
)

type AuthorizationHandler struct {
	authzService authz.Service
}

func NewAuthorizationHandler(authzService authz.Service) *AuthorizationHandler {
	return &AuthorizationHandler{
		authzService: authzService,
	}
}

func (h *AuthorizationHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	req := dto.AuthorizeRequest{
		ResponseType:        r.URL.Query().Get("response_type"),
		ClientID:            r.URL.Query().Get("client_id"),
		RedirectURI:         r.URL.Query().Get("redirect_uri"),
		Scope:               r.URL.Query().Get("scope"),
		State:               r.URL.Query().Get("state"),
		Nonce:               r.URL.Query().Get("nonce"),
		CodeChallenge:       r.URL.Query().Get("code_challenge"),
		CodeChallengeMethod: r.URL.Query().Get("code_challenge_method"),
	}

	sessionID := ""
	if cookie, err := r.Cookie("idp_session"); err == nil {
		sessionID = cookie.Value
	}

	cmd := &appauthz.AuthorizationCommand{
		SessionID:           sessionID,
		ResponseType:        req.ResponseType,
		ClientID:            req.ClientID,
		RedirectURI:         req.RedirectURI,
		Scope:               req.ScopeList(),
		State:               req.State,
		Nonce:               req.Nonce,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
	}

	result, err := h.authzService.Authorize(ctx, cmd)
	if err != nil {
		h.writeAuthorizeError(w, r, cmd, err)
		return
	}
	if result.RequireConsent {
		http.Redirect(w, r, withReturnTo(result.ConsentRedirectURI, r.URL.RequestURI()), http.StatusFound)
		return
	}
	if result.RequireLogin {
		http.Redirect(w, r, withReturnTo(result.LoginRedirectURI, r.URL.RequestURI()), http.StatusFound)
		return
	}
	redirectURL, err := buildAuthorizeSuccessRedirect(result.RedirectURI, result.Code, result.State)
	if err != nil {
		http.Error(w, "failed to build redirect url", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, redirectURL, http.StatusFound)

}
func buildAuthorizeSuccessRedirect(redirectURI, code, state string) (string, error) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		return "", err
	}

	q := u.Query()
	q.Set("code", code)
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}
func (h *AuthorizationHandler) writeAuthorizeError(
	w http.ResponseWriter,
	r *http.Request,
	cmd *appauthz.AuthorizationCommand,
	err error,
) {
	oauthErr := pkgoauth2.Error{
		Code:        "invalid_request",
		Description: err.Error(),
	}

	switch {
	case errors.Is(err, appauthz.ErrUnsupportedResponseType):
		oauthErr.Code = "unsupported_response_type"
	case errors.Is(err, appauthz.ErrInvalidScope):
		oauthErr.Code = "invalid_scope"
	case errors.Is(err, appauthz.ErrInvalidClient):
		oauthErr.Code = "unauthorized_client"
	case errors.Is(err, appauthz.ErrInvalidRedirectURI),
		errors.Is(err, appauthz.ErrInvalidCodeChallenge),
		errors.Is(err, appauthz.ErrInvalidRequest):
		oauthErr.Code = "invalid_request"
	}

	if cmd != nil && cmd.RedirectURI != "" {
		redirectURL, buildErr := buildAuthorizeErrorRedirect(cmd.RedirectURI, oauthErr, cmd.State)
		if buildErr == nil {
			http.Redirect(w, r, redirectURL, http.StatusFound)
			return
		}
	}

	http.Error(w, oauthErr.Description, http.StatusBadRequest)
}

func buildAuthorizeErrorRedirect(redirectURI string, oauthErr pkgoauth2.Error, state string) (string, error) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		return "", err
	}

	q := u.Query()
	q.Set("error", oauthErr.Code)
	if oauthErr.Description != "" {
		q.Set("error_description", oauthErr.Description)
	}
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func withReturnTo(loginURI, returnTo string) string {
	u, err := url.Parse(loginURI)
	if err != nil {
		return loginURI
	}
	q := u.Query()
	q.Set("return_to", returnTo)
	u.RawQuery = q.Encode()
	return u.String()
}
