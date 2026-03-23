package security

type Signer interface {
	Mint(claims map[string]any) (string, error)
}
