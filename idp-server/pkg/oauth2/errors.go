package oauth2

type Error struct {
	Code        string `json:"error"`
	Description string `json:"error_description,omitempty"`
}
