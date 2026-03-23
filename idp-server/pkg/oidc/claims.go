package oidc

type Claims map[string]interface{}

const (
	ClaimIssuer            = "iss"
	ClaimSubject           = "sub"
	ClaimAudience          = "aud"
	ClaimExpiration        = "exp"
	ClaimIssuedAt          = "iat"
	ClaimNotBefore         = "nbf"
	ClaimJWTID             = "jti"
	ClaimNonce             = "nonce"
	ClaimAuthorizedParty   = "azp"
	ClaimAuthTime          = "auth_time"
	ClaimName              = "name"
	ClaimPreferredUsername = "preferred_username"
	ClaimEmail             = "email"
	ClaimEmailVerified     = "email_verified"
)
