package dto

type LoginRequest struct {
	Method      string `json:"method" form:"method"`
	Username    string `json:"username" form:"username"`
	Password    string `json:"password" form:"password"`
	ReturnTo    string `json:"return_to" form:"return_to"`
	RedirectURI string `json:"redirect_uri" form:"redirect_uri"`
	State       string `json:"state" form:"state"`
	Code        string `json:"code" form:"code"`
	Nonce       string `json:"nonce" form:"nonce"`
}
