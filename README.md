# github.com/webxcom/auth-sdk

Go SDK for integrating WebXCOM DeOAuth into backend services and browser-adjacent flows.

This module is the Go port of the existing WebXCOM auth SDK. It keeps the server-side DeOAuth flow and exposes helper functions for login URL generation, but it does not try to re-create browser-only runtime behavior like popup control, `postMessage`, or `localStorage`.

## module path

```go
module github.com/webxcom/auth-sdk
```

Install it with:

```bash
go get github.com/webxcom/auth-sdk
```

## what is included

- Browser-facing helpers for login URL construction and OAuth state generation
- Server-side backend flow for `authorize -> callback -> get_token`
- Server-side refresh and logout API calls
- In-memory pending state management for a single process instance

## what is not included

- Popup window management
- `postMessage` handling
- Browser token persistence such as `localStorage`
- Distributed pending-state storage for multi-instance deployments

## base URLs

| Surface | Default URL | Meaning |
| --- | --- | --- |
| Frontend helper | `https://webxcom.com` | WebXCOM platform login URL |
| Backend | `https://api.webxcom.com` | DeOAuth server |

Note: Apps and games must be registered at https://dev.webxcom.com/. You can also find the detailed protocol documentation there.

## quick start

### frontend-style helper usage

Use this when your app needs to generate the login URL but handles browser behavior itself.

```go
package main

import (
	"fmt"

	sdk "github.com/webxcom/auth-sdk"
)

func main() {
	state, err := sdk.GenerateState()
	if err != nil {
		panic(err)
	}

	loginURL, err := sdk.BuildLoginURL(sdk.FrontendConfig{
		ClientID:    "YOUR_CLIENT_ID",
		RedirectURI: "https://yourapp.com/callback",
	}, sdk.LoginParams{State: state})
	if err != nil {
		panic(err)
	}

	fmt.Println(loginURL)
}
```

### backend usage

Use this when your backend receives a JWT and needs slot information from the DeOAuth server.

```go
package main

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	sdk "github.com/webxcom/auth-sdk"
)

func main() {
	client, err := sdk.NewBackend(sdk.BackendConfig{
		ClientID:     "YOUR_CLIENT_ID",
		ClientSecret: "YOUR_CLIENT_SECRET",
		RedirectURI:  "https://yourapp.com/getinfo",
	})
	if err != nil {
		log.Fatal(err)
	}

	http.HandleFunc("/getinfo", func(w http.ResponseWriter, r *http.Request) {
		client.HandleCallback(w, r)
	})

	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		jwt := r.URL.Query().Get("jwt")
		slotInfo, err := client.GetSlotInfo(r.Context(), jwt, sdk.AuthorizeOptions{Timeout: 15 * time.Second})
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		_ = json.NewEncoder(w).Encode(slotInfo)
	})

	log.Fatal(http.ListenAndServe(":8080", nil))
}
```

## exported API

### helper surface

- `GenerateState() (string, error)`
- `BuildLoginURL(cfg FrontendConfig, params LoginParams) (string, error)`

### backend surface

- `FrontendConfig`
- `LoginParams`
- `NewBackend(cfg BackendConfig) (*Backend, error)`
- `BackendConfig`
- `AuthorizeOptions`
- `RefreshOptions`
- `(*Backend).GetSlotInfo(ctx, jwt, opts)`
- `(*Backend).HandleCallback(w, r)`
- `(*Backend).ExchangeCode(ctx, code)`
- `(*Backend).RefreshTokens(ctx, opts)`
- `(*Backend).Logout(ctx, jwt)`
- `(*Backend).Shutdown(ctx)`
- `TokenSet`

### slot info shape

```go
type SlotInfo struct {
	ID             string
	AccessToken    string
	ContentAddress string
	TokenNickname  string
	TRCnt          int
	Code           string
}
```

## behavior notes

- The Go module uses `response_type`, not the `respose_type` typo seen in the legacy JS backend implementation.
- `RefreshTokens` and `Logout` are server-side APIs in this module. They are not browser helpers.
- Callback handling reads `state`, `success`, and `code` from the callback URL query string. In the current integration, the DeOAuth server is expected to call your registered callback URL with `POST` and include those values in the query string.
- Pending authorize state is stored in memory. Version 1 is for a single running process. It does not support shared state across multiple instances.

## security notes

- Never expose `ClientSecret` to browser code.
- `RedirectURI` must match the registered callback URL exactly.
- Use HTTPS in production.
- If you deploy multiple instances behind a load balancer, the in-memory pending state model is not enough on its own.

## local development

Override base URLs if you need local or staging servers.

```go
client, err := sdk.NewBackend(sdk.BackendConfig{
	AuthServerURL: "http://localhost:3000",
	ClientID:      "YOUR_CLIENT_ID",
	ClientSecret:  "YOUR_CLIENT_SECRET",
	RedirectURI:   "http://localhost:3070/getinfo",
})
```

```go
loginURL, err := sdk.BuildLoginURL(sdk.FrontendConfig{
	WebXCOMURL:  "http://localhost:3000",
	ClientID:    "YOUR_CLIENT_ID",
	RedirectURI: "http://localhost:3070/getinfo",
}, sdk.LoginParams{State: "custom-state"})
```

### local test server

This module also includes a small local test server that lets you exercise the SDK without depending on external network routing.

Run it with:

```bash
go run ./cmd/localtestserver
```

By default it starts two local HTTP servers:

- frontend mock: `http://127.0.0.1:8888`
- backend test server: `http://127.0.0.1:9999`

Useful routes:

- `GET http://127.0.0.1:9999/frontend/login-url`
  - returns a generated login URL and state
- `GET http://127.0.0.1:9999/login?jwt=test-jwt`
  - runs the mocked `authorize -> callback -> get_token` flow and returns `SlotInfo`
- `POST http://127.0.0.1:9999/callback`
  - callback endpoint used by the local backend flow

Example:

```bash
curl http://127.0.0.1:9999/frontend/login-url
curl "http://127.0.0.1:9999/login?jwt=test-jwt"
```

You can override the defaults with environment variables:

- `SDK_CLIENT_ID`
- `SDK_CLIENT_SECRET`
- `SDK_FRONTEND_ADDR`
- `SDK_BACKEND_ADDR`
- `SDK_FRONTEND_BASE_URL`
- `SDK_BACKEND_BASE_URL`

## release strategy

- Use standard semantic version tags on the repository root, for example `v0.1.0`, `v0.2.0`, `v1.0.0`.
- Because the module path is `github.com/webxcom/auth-sdk`, you can ship `v0` and `v1` tags without changing the module path.
- If you ever publish `v2` or later with breaking changes, the module path must become `github.com/webxcom/auth-sdk/v2` and the code must live under that versioned module path.
- Tag from the repository root that contains this `go.mod`, not from a parent mono-repo path.

## development checks

```bash
go test ./...
go test -race ./...
```

## license

MIT
