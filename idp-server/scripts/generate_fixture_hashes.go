package main

import (
	"fmt"

	infrasecurity "idp-server/internal/infrastructure/security"
)

func main() {
	verifier := infrasecurity.NewPasswordVerifier()
	fixtures := []struct {
		Name  string
		Plain string
	}{
		{Name: "alice", Plain: "alice123"},
		{Name: "bob", Plain: "bob123"},
		{Name: "locked_user", Plain: "locked123"},
		{Name: "web-client", Plain: "secret123"},
		{Name: "service-client", Plain: "service123"},
	}

	for _, fixture := range fixtures {
		hash, err := verifier.HashPassword(fixture.Plain)
		if err != nil {
			panic(err)
		}

		fmt.Printf("%s %s\n", fixture.Name, hash)
	}
}
