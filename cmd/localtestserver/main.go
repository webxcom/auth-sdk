package main

import (
	"log"
	"net/http"
	"os"

	"github.com/webxcom/auth-sdk/internal/localtestserver"
)

func envOrDefault(key, fallback string) string {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	return value
}

func main() {
	clientID := envOrDefault("SDK_CLIENT_ID", "local-client-id")
	clientSecret := envOrDefault("SDK_CLIENT_SECRET", "local-client-secret")
	frontendAddr := envOrDefault("SDK_FRONTEND_ADDR", ":8888")
	backendAddr := envOrDefault("SDK_BACKEND_ADDR", ":9999")
	frontendBaseURL := envOrDefault("SDK_FRONTEND_BASE_URL", "http://127.0.0.1:8888")
	backendBaseURL := envOrDefault("SDK_BACKEND_BASE_URL", "http://127.0.0.1:9999")

	app := localtestserver.New(clientID, clientSecret)
	localtestserver.MustConfigure(app, frontendBaseURL, backendBaseURL)

	frontendServer := &http.Server{Addr: frontendAddr, Handler: app.FrontendHandler()}
	backendServer := &http.Server{Addr: backendAddr, Handler: app.BackendHandler()}

	go func() {
		log.Printf("local frontend mock listening on %s", frontendBaseURL)
		if err := frontendServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("frontend server failed: %v", err)
		}
	}()

	log.Printf("local backend test server listening on %s", backendBaseURL)
	log.Printf("try: %s/frontend/login-url", backendBaseURL)
	log.Printf("try: %s/login?jwt=test-jwt", backendBaseURL)
	if err := backendServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("backend server failed: %v", err)
	}
}
