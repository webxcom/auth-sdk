package sdk

// SlotInfo represents the slot/account payload returned by the DeOAuth server.
// SlotInfo는 DeOAuth 서버가 반환하는 슬롯/계정 페이로드를 나타낸다.
type SlotInfo struct {
	ID             string `json:"id"`
	AccessToken    string `json:"access_token"`
	ContentAddress string `json:"content_address"`
	TokenNickname  string `json:"token_nickname"`
	TRCnt          int    `json:"tr_cnt"`
	Code           string `json:"code"`
}

// TokenSet represents refreshed or issued token values.
// TokenSet은 갱신되거나 발급된 토큰 값을 나타낸다.
type TokenSet struct {
	AccessToken  string `json:"access_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Code         string `json:"code,omitempty"`
	JWT          string `json:"jwt,omitempty"`
}
