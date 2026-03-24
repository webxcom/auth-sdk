package sdk

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
)

const (
	defaultWebXCOMURL    = "https://webxcom.com"
	defaultAuthServerURL = "https://api.webxcom.com"
	defaultResponseType  = "code"
)

// FrontendConfig stores browser-facing login URL settings.
// FrontendConfig는 브라우저 측 로그인 URL 설정을 보관한다.
type FrontendConfig struct {
	WebXCOMURL   string
	ClientID     string
	RedirectURI  string
	ResponseType string
}

// LoginParams stores per-request login URL values.
// LoginParams는 요청별 로그인 URL 값을 보관한다.
type LoginParams struct {
	State string
}

// GenerateState creates a cryptographically random OAuth state string.
// GenerateState는 암호학적으로 안전한 OAuth state 문자열을 생성한다.
func GenerateState() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

// BuildLoginURL builds the login URL contract used by the browser integration.
// BuildLoginURL은 브라우저 연동에서 사용하는 로그인 URL 계약을 생성한다.
func BuildLoginURL(cfg FrontendConfig, params LoginParams) (string, error) {
	if cfg.ClientID == "" {
		return "", fmt.Errorf("clientID required")
	}
	if cfg.RedirectURI == "" {
		return "", fmt.Errorf("redirectURI required")
	}
	if params.State == "" {
		return "", fmt.Errorf("state required")
	}

	base := strings.TrimRight(cfg.WebXCOMURL, "/")
	if base == "" {
		base = defaultWebXCOMURL
	}
	responseType := cfg.ResponseType
	if responseType == "" {
		responseType = defaultResponseType
	}

	values := url.Values{}
	values.Set("client_id", cfg.ClientID)
	values.Set("redirect_uri", cfg.RedirectURI)
	values.Set("response_type", responseType)
	values.Set("state", params.State)

	return base + "/oauth/login?" + values.Encode(), nil
}
