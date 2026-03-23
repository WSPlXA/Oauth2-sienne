package main

import (
	"errors"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"idp-server/internal/bootstrap"
)

const defaultListenAddr = ":8080"

func main() {
	app, err := bootstrap.Wire()
	if err != nil {
		log.Fatalf("bootstrap error: %v", err)
	}

	server := &http.Server{
		Addr:              getEnvString("LISTEN_ADDR", defaultListenAddr),
		Handler:           app.Router,
		ReadHeaderTimeout: 3 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	log.Printf("listening on %s", server.Addr)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("server error: %v", err)
	}
}

func getEnvString(key, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	return value
}
