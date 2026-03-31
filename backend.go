package sdk

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const defaultTimeout = 15 * time.Second

// BackendConfig configures the server-side SDK behavior.
// BackendConfig는 서버 측 SDK 동작을 구성한다.
type BackendConfig struct {
	AuthServerURL string
	ClientID      string
	ClientSecret  string
	RedirectURI   string
	HTTPClient    *http.Client
}

// AuthorizeOptions configures authorize/callback waiting behavior.
// AuthorizeOptions는 authorize/callback 대기 동작을 구성한다.
type AuthorizeOptions struct {
	Timeout time.Duration
}

// RefreshOptions configures the server-side refresh API call.
// RefreshOptions는 서버 측 refresh API 호출을 구성한다.
type RefreshOptions struct {
	RefreshToken string
	Code         string
}

// Backend is the Go port of the server-side DeOAuth SDK.
// Backend는 서버 측 DeOAuth SDK의 Go 포트 구현체다.
type Backend struct {
	authServerURL string
	clientID      string
	clientSecret  string
	redirectURI   string
	httpClient    *http.Client

	mu      sync.Mutex
	pending map[string]chan callbackResult
	closed  bool
}

type callbackResult struct {
	slot SlotInfo
	err  error
}

type authorizeResponse struct {
	Success bool   `json:"success"`
	Code    string `json:"code"`
	Msg     string `json:"msg"`
}

type refreshResponse struct {
	Success      bool   `json:"success"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	Code         string `json:"code"`
	Message      string `json:"message"`
}

type tokenEnvelope struct {
	Data []SlotInfo `json:"data"`

	ID             string `json:"id"`
	AccessToken    string `json:"access_token"`
	ContentAddress string `json:"content_address"`
	TokenNickname  string `json:"token_nickname"`
	TRCnt          int    `json:"tr_cnt"`
	Code           string `json:"code"`
}

// NewBackend creates a backend SDK instance with validated configuration.
// NewBackend는 검증된 설정으로 backend SDK 인스턴스를 생성한다.
func NewBackend(cfg BackendConfig) (*Backend, error) {
	if cfg.ClientID == "" {
		return nil, fmt.Errorf("clientID required")
	}
	if cfg.ClientSecret == "" {
		return nil, fmt.Errorf("clientSecret required")
	}
	if cfg.RedirectURI == "" {
		return nil, fmt.Errorf("redirectURI required")
	}

	base := strings.TrimRight(cfg.AuthServerURL, "/")
	if base == "" {
		base = defaultAuthServerURL
	}

	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: defaultTimeout}
	}

	return &Backend{
		authServerURL: base,
		clientID:      cfg.ClientID,
		clientSecret:  cfg.ClientSecret,
		redirectURI:   cfg.RedirectURI,
		httpClient:    httpClient,
		pending:       make(map[string]chan callbackResult),
	}, nil
}

// GetSlotInfo runs authorize and waits for the callback/code exchange flow.
// GetSlotInfo는 authorize를 실행하고 callback/code exchange 흐름을 기다린다.
func (b *Backend) GetSlotInfo(ctx context.Context, jwt string, opts AuthorizeOptions) (SlotInfo, error) {
	if jwt == "" {
		return SlotInfo{}, fmt.Errorf("jwt required")
	}

	state, err := GenerateState()
	if err != nil {
		return SlotInfo{}, err
	}

	waiter, err := b.registerPending(state)
	if err != nil {
		return SlotInfo{}, err
	}
	defer b.removePending(state)

	if err := b.authorize(ctx, jwt, state); err != nil {
		return SlotInfo{}, err
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()

	select {
	case <-ctx.Done():
		return SlotInfo{}, ctx.Err()
	case <-deadline.C:
		return SlotInfo{}, fmt.Errorf("authorize callback timeout")
	case result := <-waiter:
		return result.slot, result.err
	}
}

// HandleCallback resolves a pending authorize request from the DeOAuth callback.
// HandleCallback은 DeOAuth callback으로부터 대기 중인 authorize 요청을 해제한다.
func (b *Backend) HandleCallback(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]bool{"received": true})

	state := r.URL.Query().Get("state")
	if state == "" {
		return
	}

	waiter := b.getPending(state)
	if waiter == nil {
		return
	}

	if r.URL.Query().Get("success") != "1" {
		code := r.URL.Query().Get("code")
		if code != "" {
			b.resolvePending(state, callbackResult{err: fmt.Errorf("authorize callback rejected (code: %s)", code)})
			return
		}
		b.resolvePending(state, callbackResult{err: fmt.Errorf("authorize callback rejected")})
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		b.resolvePending(state, callbackResult{err: fmt.Errorf("callback code missing")})
		return
	}

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
		defer cancel()
		slot, err := b.ExchangeCode(ctx, code)
		b.resolvePending(state, callbackResult{slot: slot, err: err})
	}()
}

// ExchangeCode exchanges the callback code for slot information.
// ExchangeCode는 callback code를 슬롯 정보로 교환한다.
func (b *Backend) ExchangeCode(ctx context.Context, code string) (SlotInfo, error) {
	if code == "" {
		return SlotInfo{}, fmt.Errorf("code required")
	}

	payload := map[string]string{
		"grant_type":   "code",
		"code":         code,
		"redirect_uri": b.redirectURI,
	}

	headers := map[string]string{
		"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte(b.clientID+":"+b.clientSecret)),
	}

	var response tokenEnvelope
	if err := b.postJSON(ctx, b.authServerURL+"/v1/oauth-meta/get_token", headers, payload, &response); err != nil {
		return SlotInfo{}, err
	}

	if len(response.Data) > 0 {
		return response.Data[0], nil
	}

	return SlotInfo{
		ID:             response.ID,
		AccessToken:    response.AccessToken,
		ContentAddress: response.ContentAddress,
		TokenNickname:  response.TokenNickname,
		TRCnt:          response.TRCnt,
		Code:           response.Code,
	}, nil
}

// RefreshTokens calls the refresh endpoint as a server-side API.
// RefreshTokens는 서버 측 API로 refresh 엔드포인트를 호출한다.
func (b *Backend) RefreshTokens(ctx context.Context, opts RefreshOptions) (TokenSet, error) {
	if opts.RefreshToken == "" {
		return TokenSet{}, fmt.Errorf("refreshToken required")
	}

	payload := map[string]string{
		"refresh_token": opts.RefreshToken,
		"client_id":     b.clientID,
		"client_secret": b.clientSecret,
		"redirect_uri":  b.redirectURI,
		"code":          opts.Code,
	}

	var response refreshResponse
	if err := b.postJSON(ctx, b.authServerURL+"/oauth/token/refresh", nil, payload, &response); err != nil {
		return TokenSet{}, err
	}
	if !response.Success {
		if response.Message != "" {
			return TokenSet{}, fmt.Errorf("token refresh failed: %s", response.Message)
		}
		return TokenSet{}, fmt.Errorf("token refresh failed")
	}

	return TokenSet{
		AccessToken:  response.AccessToken,
		RefreshToken: response.RefreshToken,
		Code:         response.Code,
	}, nil
}

// Logout calls the logout endpoint as a server-side API.
// Logout은 서버 측 API로 logout 엔드포인트를 호출한다.
func (b *Backend) Logout(ctx context.Context, jwt string) error {
	if jwt == "" {
		return fmt.Errorf("jwt required")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, b.authServerURL+"/oauth/logout", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+jwt)

	resp, err := b.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("logout failed: http %d", resp.StatusCode)
	}

	return nil
}

// Shutdown rejects future waits and clears in-memory pending state.
// Shutdown은 향후 대기를 거부하고 메모리 기반 pending state를 정리한다.
func (b *Backend) Shutdown(_ context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return nil
	}
	b.closed = true

	for state, waiter := range b.pending {
		select {
		case waiter <- callbackResult{err: fmt.Errorf("shutdown")}:
		default:
		}
		delete(b.pending, state)
	}

	return nil
}

func (b *Backend) authorize(ctx context.Context, jwt, state string) error {
	values := url.Values{}
	values.Set("client_id", b.clientID)
	values.Set("redirect_uri", b.redirectURI)
	values.Set("respose_type", defaultResponseType) // Node.js SDK 호환: "respose_type" (오타) — DeOAuth 서버가 이 파라미터명을 기대한다
	values.Set("state", state)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, b.authServerURL+"/v1/oauth-meta/authorize?"+values.Encode(), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+jwt)

	resp, err := b.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("authorize failed: http %d", resp.StatusCode)
	}

	var payload authorizeResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return err
	}
	if !payload.Success {
		if payload.Code != "" {
			return fmt.Errorf("authorize failed (%s)", payload.Code)
		}
		if payload.Msg != "" {
			return fmt.Errorf("authorize failed: %s", payload.Msg)
		}
		return fmt.Errorf("authorize failed")
	}

	return nil
}

func (b *Backend) postJSON(ctx context.Context, endpoint string, headers map[string]string, payload any, out any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	resp, err := b.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("http %d", resp.StatusCode)
	}

	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (b *Backend) registerPending(state string) (chan callbackResult, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return nil, fmt.Errorf("backend shutdown")
	}

	ch := make(chan callbackResult, 1)
	b.pending[state] = ch
	return ch, nil
}

func (b *Backend) getPending(state string) chan callbackResult {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.pending[state]
}

func (b *Backend) resolvePending(state string, result callbackResult) {
	b.mu.Lock()
	waiter, ok := b.pending[state]
	if ok {
		delete(b.pending, state)
	}
	b.mu.Unlock()

	if !ok {
		return
	}

	select {
	case waiter <- result:
	default:
	}
}

func (b *Backend) removePending(state string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.pending, state)
}
