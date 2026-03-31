package sdk

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestBuildLoginURLUsesDefaultResponseType(t *testing.T) {
	cfg := FrontendConfig{
		ClientID:    "client-123",
		RedirectURI: "https://app.example.com/callback",
	}

	loginURL, err := BuildLoginURL(cfg, LoginParams{State: "state-abc"})
	if err != nil {
		t.Fatalf("BuildLoginURL returned error: %v", err)
	}

	parsed, err := url.Parse(loginURL)
	if err != nil {
		t.Fatalf("url.Parse returned error: %v", err)
	}

	if got, want := parsed.Scheme, "https"; got != want {
		t.Fatalf("scheme = %q, want %q", got, want)
	}
	if got, want := parsed.Host, "webxcom.com"; got != want {
		t.Fatalf("host = %q, want %q", got, want)
	}
	if got, want := parsed.Path, "/oauth/login"; got != want {
		t.Fatalf("path = %q, want %q", got, want)
	}
	if got, want := parsed.Query().Get("client_id"), "client-123"; got != want {
		t.Fatalf("client_id = %q, want %q", got, want)
	}
	if got, want := parsed.Query().Get("redirect_uri"), "https://app.example.com/callback"; got != want {
		t.Fatalf("redirect_uri = %q, want %q", got, want)
	}
	if got, want := parsed.Query().Get("response_type"), "code"; got != want {
		t.Fatalf("response_type = %q, want %q", got, want)
	}
	if got, want := parsed.Query().Get("state"), "state-abc"; got != want {
		t.Fatalf("state = %q, want %q", got, want)
	}
}

func TestGenerateStateReturnsDistinctNonEmptyValues(t *testing.T) {
	first, err := GenerateState()
	if err != nil {
		t.Fatalf("GenerateState first call returned error: %v", err)
	}
	second, err := GenerateState()
	if err != nil {
		t.Fatalf("GenerateState second call returned error: %v", err)
	}

	if first == "" {
		t.Fatal("first generated state is empty")
	}
	if second == "" {
		t.Fatal("second generated state is empty")
	}
	if first == second {
		t.Fatalf("generated states must differ, both were %q", first)
	}
}

func TestNewBackendRequiresMandatoryFields(t *testing.T) {
	_, err := NewBackend(BackendConfig{})
	if err == nil {
		t.Fatal("NewBackend should reject missing configuration")
	}
}

func TestGetSlotInfoUsesResponseTypeAndResolvesAfterCallback(t *testing.T) {
	t.Parallel()

	authorizeCalls := make(chan url.Values, 1)
	tokenBodies := make(chan map[string]any, 1)

	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/oauth-meta/authorize":
			authorizeCalls <- r.URL.Query()
			if got, want := r.Header.Get("Authorization"), "Bearer jwt-123"; got != want {
				t.Errorf("Authorization header = %q, want %q", got, want)
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true})
		case "/v1/oauth-meta/get_token":
			defer r.Body.Close()
			var payload map[string]any
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatalf("decode get_token payload: %v", err)
			}
			tokenBodies <- payload

			user, pass, ok := basicAuthParts(r.Header.Get("Authorization"))
			if !ok {
				t.Fatalf("missing valid basic auth header")
			}
			if user != "client-123" || pass != "secret-456" {
				t.Fatalf("basic auth = %q/%q, want client-123/secret-456", user, pass)
			}

			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": []map[string]any{{
					"id":              "slot-1",
					"access_token":    "slot-token",
					"content_address": "0xabc",
					"token_nickname":  "main-slot",
					"tr_cnt":          7,
					"code":            "code-789",
				}},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer authServer.Close()

	backend, err := NewBackend(BackendConfig{
		AuthServerURL: authServer.URL,
		ClientID:      "client-123",
		ClientSecret:  "secret-456",
		RedirectURI:   "https://app.example.com/getinfo",
	})
	if err != nil {
		t.Fatalf("NewBackend returned error: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	resultCh := make(chan struct {
		slot SlotInfo
		err  error
	}, 1)

	go func() {
		slot, err := backend.GetSlotInfo(ctx, "jwt-123", AuthorizeOptions{Timeout: time.Second})
		resultCh <- struct {
			slot SlotInfo
			err  error
		}{slot: slot, err: err}
	}()

	query := <-authorizeCalls
	if got, want := query.Get("response_type"), "code"; got != want {
		t.Fatalf("response_type = %q, want %q", got, want)
	}
	if got := query.Get("respose_type"); got != "" {
		t.Fatalf("respose_type should be absent, got %q", got)
	}
	state := query.Get("state")
	if state == "" {
		t.Fatal("state should not be empty")
	}

	req := httptest.NewRequest(http.MethodPost, "/getinfo?state="+url.QueryEscape(state)+"&success=1&code=code-789", nil)
	rec := httptest.NewRecorder()
	backend.HandleCallback(rec, req)

	if got, want := rec.Code, http.StatusOK; got != want {
		t.Fatalf("callback status = %d, want %d", got, want)
	}

	result := <-resultCh
	if result.err != nil {
		t.Fatalf("GetSlotInfo returned error: %v", result.err)
	}
	if got, want := result.slot.ID, "slot-1"; got != want {
		t.Fatalf("slot.ID = %q, want %q", got, want)
	}
	if got, want := result.slot.AccessToken, "slot-token"; got != want {
		t.Fatalf("slot.AccessToken = %q, want %q", got, want)
	}

	body := <-tokenBodies
	if got, want := body["grant_type"], "code"; got != want {
		t.Fatalf("grant_type = %v, want %q", got, want)
	}
	if got, want := body["redirect_uri"], "https://app.example.com/getinfo"; got != want {
		t.Fatalf("redirect_uri = %v, want %q", got, want)
	}
}

func TestRefreshTokensPostsServerSidePayload(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got, want := r.URL.Path, "/oauth/token/refresh"; got != want {
			t.Fatalf("path = %q, want %q", got, want)
		}
		defer r.Body.Close()

		var payload map[string]any
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("decode refresh payload: %v", err)
		}
		if got, want := payload["client_secret"], "secret-456"; got != want {
			t.Fatalf("client_secret = %v, want %q", got, want)
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success":       true,
			"access_token":  "new-access",
			"refresh_token": "new-refresh",
			"code":          "new-code",
		})
	}))
	defer server.Close()

	backend, err := NewBackend(BackendConfig{
		AuthServerURL: server.URL,
		ClientID:      "client-123",
		ClientSecret:  "secret-456",
		RedirectURI:   "https://app.example.com/getinfo",
	})
	if err != nil {
		t.Fatalf("NewBackend returned error: %v", err)
	}

	tokens, err := backend.RefreshTokens(context.Background(), RefreshOptions{
		RefreshToken: "refresh-123",
		Code:         "code-789",
	})
	if err != nil {
		t.Fatalf("RefreshTokens returned error: %v", err)
	}

	if got, want := tokens.AccessToken, "new-access"; got != want {
		t.Fatalf("AccessToken = %q, want %q", got, want)
	}
	if got, want := tokens.RefreshToken, "new-refresh"; got != want {
		t.Fatalf("RefreshToken = %q, want %q", got, want)
	}
}

func TestLogoutSendsBearerToken(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got, want := r.URL.Path, "/oauth/logout"; got != want {
			t.Fatalf("path = %q, want %q", got, want)
		}
		if got, want := r.Header.Get("Authorization"), "Bearer jwt-logout"; got != want {
			t.Fatalf("Authorization = %q, want %q", got, want)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	backend, err := NewBackend(BackendConfig{
		AuthServerURL: server.URL,
		ClientID:      "client-123",
		ClientSecret:  "secret-456",
		RedirectURI:   "https://app.example.com/getinfo",
	})
	if err != nil {
		t.Fatalf("NewBackend returned error: %v", err)
	}

	if err := backend.Logout(context.Background(), "jwt-logout"); err != nil {
		t.Fatalf("Logout returned error: %v", err)
	}
}

func TestHandleCallbackUsesDetachedContextForExchange(t *testing.T) {
	t.Parallel()

	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/oauth-meta/authorize":
			redirectURI := r.URL.Query().Get("redirect_uri")
			state := r.URL.Query().Get("state")
			go func() {
				_, _ = http.Post(redirectURI+"?state="+url.QueryEscape(state)+"&success=1&code=server-code", "application/json", strings.NewReader("{}"))
			}()
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true})
		case "/v1/oauth-meta/get_token":
			select {
			case <-r.Context().Done():
				t.Fatal("token exchange context was canceled before request completed")
			default:
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": []map[string]any{{
					"id":              "slot-detached",
					"access_token":    "detached-access-token",
					"content_address": "0xdetached",
					"token_nickname":  "detached-slot",
					"tr_cnt":          2,
					"code":            "server-code",
				}},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer authServer.Close()

	backend, err := NewBackend(BackendConfig{
		AuthServerURL: authServer.URL,
		ClientID:      "client-123",
		ClientSecret:  "secret-456",
		RedirectURI:   "http://127.0.0.1:19999/callback",
	})
	if err != nil {
		t.Fatalf("NewBackend returned error: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/callback", backend.HandleCallback)
	callbackServer := httptest.NewServer(mux)
	defer callbackServer.Close()

	backend.redirectURI = callbackServer.URL + "/callback"

	slot, err := backend.GetSlotInfo(context.Background(), "jwt-detached", AuthorizeOptions{Timeout: time.Second})
	if err != nil {
		t.Fatalf("GetSlotInfo returned error: %v", err)
	}
	if got, want := slot.ID, "slot-detached"; got != want {
		t.Fatalf("slot.ID = %q, want %q", got, want)
	}
}

func basicAuthParts(header string) (string, string, bool) {
	const prefix = "Basic "
	if !strings.HasPrefix(header, prefix) {
		return "", "", false
	}

	decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(header, prefix))
	if err != nil {
		return "", "", false
	}
	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	return parts[0], parts[1], true
}
