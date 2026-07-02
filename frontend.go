package sdk

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
)

const (
	// 2026-07-02 기본 도메인 교체: webxcom.com → altscodex.com (브랜드 이전).
	// 사유: 플랫폼 공식 브랜드가 AltsCodex(.com) 로 이전 완료. JS(@altscodex/sdk)·Python
	//       (altscodex-sdk) SDK 는 이미 altscodex 도메인이 기본값이며 Go 만 레거시로 남아 있었다.
	// 구 도메인(webxcom.com/api.webxcom.com)은 현재 동일 서버로 라우팅되므로 기존 통합자도
	// 동작이 바뀌지 않지만, 장기적으로 폐기 대상이다. 명시적으로 URL 을 넣는 통합자는 무관.
	defaultWebXCOMURL    = "https://altscodex.com"
	defaultAuthServerURL = "https://api.altscodex.com"
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
