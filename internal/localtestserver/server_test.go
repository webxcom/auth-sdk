package localtestserver

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestFrontendLoginURLRouteReturnsLocalSDKURL(t *testing.T) {
	app := New("client-123", "secret-456")

	frontend := httptest.NewServer(app.FrontendHandler())
	defer frontend.Close()

	backend := httptest.NewServer(app.BackendHandler())
	defer backend.Close()

	if err := app.Configure(frontend.URL, backend.URL); err != nil {
		t.Fatalf("Configure returned error: %v", err)
	}

	resp, err := http.Get(backend.URL + "/frontend/login-url")
	if err != nil {
		t.Fatalf("GET /frontend/login-url failed: %v", err)
	}
	defer resp.Body.Close()

	if got, want := resp.StatusCode, http.StatusOK; got != want {
		t.Fatalf("status = %d, want %d", got, want)
	}

	var payload struct {
		LoginURL string `json:"login_url"`
		State    string `json:"state"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if payload.State == "" {
		t.Fatal("state should not be empty")
	}

	parsed, err := url.Parse(payload.LoginURL)
	if err != nil {
		t.Fatalf("url.Parse returned error: %v", err)
	}

	if got, want := parsed.Scheme+"://"+parsed.Host, frontend.URL; got != want {
		t.Fatalf("login host = %q, want %q", got, want)
	}
	if got, want := parsed.Path, "/oauth/login"; got != want {
		t.Fatalf("path = %q, want %q", got, want)
	}
	if got, want := parsed.Query().Get("client_id"), "client-123"; got != want {
		t.Fatalf("client_id = %q, want %q", got, want)
	}
	if got, want := parsed.Query().Get("redirect_uri"), backend.URL+"/callback"; got != want {
		t.Fatalf("redirect_uri = %q, want %q", got, want)
	}
	if got := parsed.Query().Get("state"); got == "" {
		t.Fatal("state query param should not be empty")
	}
}

func TestLoginRouteCompletesMockedAuthFlow(t *testing.T) {
	app := New("client-123", "secret-456")

	frontend := httptest.NewServer(app.FrontendHandler())
	defer frontend.Close()

	backend := httptest.NewServer(app.BackendHandler())
	defer backend.Close()

	if err := app.Configure(frontend.URL, backend.URL); err != nil {
		t.Fatalf("Configure returned error: %v", err)
	}

	resp, err := http.Get(backend.URL + "/login?jwt=test-jwt")
	if err != nil {
		t.Fatalf("GET /login failed: %v", err)
	}
	defer resp.Body.Close()

	if got, want := resp.StatusCode, http.StatusOK; got != want {
		t.Fatalf("status = %d, want %d", got, want)
	}

	var slot struct {
		ID             string `json:"id"`
		AccessToken    string `json:"access_token"`
		ContentAddress string `json:"content_address"`
		TokenNickname  string `json:"token_nickname"`
		TRCnt          int    `json:"tr_cnt"`
		Code           string `json:"code"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&slot); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if got, want := slot.ID, "local-slot"; got != want {
		t.Fatalf("slot.ID = %q, want %q", got, want)
	}
	if got, want := slot.AccessToken, "local-access-token"; got != want {
		t.Fatalf("slot.AccessToken = %q, want %q", got, want)
	}
	if got, want := slot.Code, "local-auth-code"; got != want {
		t.Fatalf("slot.Code = %q, want %q", got, want)
	}
}
