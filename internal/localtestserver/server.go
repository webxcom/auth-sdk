package localtestserver

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"

	sdk "github.com/webxcom/auth-sdk"
)

type App struct {
	clientID     string
	clientSecret string

	mu           sync.RWMutex
	frontendURL  string
	backendURL   string
	backend      *sdk.Backend
	callbackPath string
	loginPath    string
}

func New(clientID, clientSecret string) *App {
	return &App{
		clientID:     clientID,
		clientSecret: clientSecret,
		callbackPath: "/callback",
		loginPath:    "/login",
	}
}

func (a *App) Configure(frontendURL, backendURL string) error {
	frontendURL = strings.TrimRight(frontendURL, "/")
	backendURL = strings.TrimRight(backendURL, "/")

	backend, err := sdk.NewBackend(sdk.BackendConfig{
		AuthServerURL: frontendURL,
		ClientID:      a.clientID,
		ClientSecret:  a.clientSecret,
		RedirectURI:   backendURL + a.callbackPath,
	})
	if err != nil {
		return err
	}

	a.mu.Lock()
	a.frontendURL = frontendURL
	a.backendURL = backendURL
	a.backend = backend
	a.mu.Unlock()

	return nil
}

func (a *App) FrontendHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", a.handleFrontendIndex)
	mux.HandleFunc("/oauth/login", a.handleFrontendLogin)
	mux.HandleFunc("/v1/oauth-meta/authorize", a.handleAuthorize)
	mux.HandleFunc("/v1/oauth-meta/get_token", a.handleGetToken)
	mux.HandleFunc("/oauth/token/refresh", a.handleRefresh)
	mux.HandleFunc("/oauth/logout", a.handleLogout)
	return mux
}

func (a *App) BackendHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", a.handleBackendIndex)
	mux.HandleFunc("/frontend/login-url", a.handleFrontendLoginURL)
	mux.HandleFunc(a.loginPath, a.handleBackendLogin)
	mux.HandleFunc(a.callbackPath, a.handleCallback)
	return mux
}

func (a *App) frontendConfig() (string, string) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.frontendURL, a.backendURL + a.callbackPath
}

func (a *App) currentBackend() *sdk.Backend {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.backend
}

func (a *App) handleFrontendIndex(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte("local auth frontend mock is running\n"))
}

func (a *App) handleBackendIndex(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte("local auth backend test server is running\n"))
}

func (a *App) handleFrontendLogin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"message":       "local oauth login page",
		"client_id":     r.URL.Query().Get("client_id"),
		"redirect_uri":  r.URL.Query().Get("redirect_uri"),
		"response_type": r.URL.Query().Get("response_type"),
		"state":         r.URL.Query().Get("state"),
	})
}

func (a *App) handleFrontendLoginURL(w http.ResponseWriter, _ *http.Request) {
	frontendURL, redirectURI := a.frontendConfig()
	state, err := sdk.GenerateState()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	loginURL, err := sdk.BuildLoginURL(sdk.FrontendConfig{
		WebXCOMURL:  frontendURL,
		ClientID:    a.clientID,
		RedirectURI: redirectURI,
	}, sdk.LoginParams{State: state})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"state":     state,
		"login_url": loginURL,
	})
}

func (a *App) handleBackendLogin(w http.ResponseWriter, r *http.Request) {
	backend := a.currentBackend()
	if backend == nil {
		http.Error(w, "backend not configured", http.StatusInternalServerError)
		return
	}
	jwt := r.URL.Query().Get("jwt")
	if jwt == "" {
		http.Error(w, "jwt required", http.StatusBadRequest)
		return
	}
	slotInfo, err := backend.GetSlotInfo(r.Context(), jwt, sdk.AuthorizeOptions{})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(slotInfo)
}

func (a *App) handleCallback(w http.ResponseWriter, r *http.Request) {
	backend := a.currentBackend()
	if backend == nil {
		http.Error(w, "backend not configured", http.StatusInternalServerError)
		return
	}
	backend.HandleCallback(w, r)
}

func (a *App) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	redirectURI := r.URL.Query().Get("redirect_uri")
	state := r.URL.Query().Get("state")
	if redirectURI == "" || state == "" {
		http.Error(w, "redirect_uri and state required", http.StatusBadRequest)
		return
	}
	if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
		http.Error(w, "missing bearer token", http.StatusUnauthorized)
		return
	}

	callbackURL, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	query := callbackURL.Query()
	query.Set("state", state)
	query.Set("success", "1")
	query.Set("code", "local-auth-code")
	callbackURL.RawQuery = query.Encode()

	go func(target string) {
		_, _ = http.Post(target, "application/json", strings.NewReader("{}"))
	}(callbackURL.String())

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

func (a *App) handleGetToken(w http.ResponseWriter, r *http.Request) {
	if !validBasicAuth(r.Header.Get("Authorization"), a.clientID, a.clientSecret) {
		http.Error(w, "invalid basic auth", http.StatusUnauthorized)
		return
	}
	defer r.Body.Close()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var payload map[string]string
	if err := json.Unmarshal(body, &payload); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	code := payload["code"]
	if code == "" {
		http.Error(w, "code required", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"data": []map[string]any{{
			"id":              "local-slot",
			"access_token":    "local-access-token",
			"content_address": "0xlocal",
			"token_nickname":  "local-test-slot",
			"tr_cnt":          1,
			"code":            code,
		}},
	})
}

func (a *App) handleRefresh(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"success":       true,
		"access_token":  "refreshed-access-token",
		"refresh_token": "refreshed-refresh-token",
		"code":          "refreshed-code",
	})
}

func (a *App) handleLogout(w http.ResponseWriter, r *http.Request) {
	if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
		http.Error(w, "missing bearer token", http.StatusUnauthorized)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

func validBasicAuth(header, user, pass string) bool {
	req, err := http.NewRequest(http.MethodGet, "http://localhost", nil)
	if err != nil {
		return false
	}
	req.Header.Set("Authorization", header)
	gotUser, gotPass, ok := req.BasicAuth()
	if !ok {
		return false
	}
	return gotUser == user && gotPass == pass
}

func MustConfigure(app *App, frontendURL, backendURL string) {
	if err := app.Configure(frontendURL, backendURL); err != nil {
		panic(fmt.Sprintf("configure local test server: %v", err))
	}
}
