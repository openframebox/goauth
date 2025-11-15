# goauth

Pluggable authentication for Go. Build username/password or JWT-based auth with a simple strategy interface, a configurable JWT access-token + refresh-token issuer, and typed errors for clean, predictable error handling.

Works as an auth core you can drop into HTTP APIs, gRPC, or CLIs.

## Installation

```
go get github.com/openframebox/goauth
```

## Concepts

- Strategy: pluggable auth mechanism that returns a user (e.g., Local, JWT, OAuth, SSO). Implement `Name()` and `Authenticate()`.
- Authenticatable: minimal user interface (`GetID`, `GetUsername`, `GetEmail`, `GetExtra`). A default `User` is included.
- TokenIssuer: service that creates/verifies access tokens and manages refresh tokens. `DefaultTokenIssuer` uses HS256 JWT for access tokens and UUIDs for refresh tokens.
- Typed Errors: errors are categorized (`CredentialError`, `TokenError`, `ConfigError`, `NotFoundError`, `InternalError`) so callers can map responses consistently.

## Quick Start

See `example/main.go` for a runnable demo of login → JWT auth → refresh:

```
go run ./example
```

## Initialization

Create a token issuer and the orchestrator, then register strategies:

```go
package main

import (
    "context"
    goauth "github.com/openframebox/goauth"
)

func setup() *goauth.GoAuth {
    // 1) Configure token issuer
    ti := goauth.NewDefaultTokenIssuer("supersecret")
    ti.SetIssuer("api.example.com")
    ti.SetAudience([]string{"api.example.com"})

    // Required for refresh tokens: where/how to store them
    ti.StoreRefreshTokenWith(func(ctx context.Context, a goauth.Authenticatable, tok *goauth.Token, refreshing bool) error {
        // persist tok.Value with user a.GetID() and rotation behavior
        return nil
    })
    ti.ValidateRefreshTokenWith(func(ctx context.Context, token string) (goauth.Authenticatable, error) {
        // lookup token → user; return &goauth.TokenError on invalid
        return &goauth.User{ID: "user-123"}, nil
    })

    // Optional: attach extra claims to access JWTs
    ti.SetExtraClaimsWith(func(ctx context.Context, a goauth.Authenticatable) map[string]any {
        return map[string]any{"role": "admin"}
    })

    // Optional: convert JWT claims → full user (by default: ID/Username/Email)
    // ti.ConvertAccessTokenClaimsWith(func(ctx context.Context, c *goauth.TokenClaims) (goauth.Authenticatable, error) {
    //     return &goauth.User{ID: c.Subject}, nil
    // })

    // 2) Build the orchestrator and register strategies
    ga := goauth.New()
    ga.SetTokenIssuer(ti)

    // Local username/password strategy
    ga.RegisterStrategy(&goauth.LocalStrategy{LookupUserWith: func(p goauth.AuthParams) (goauth.Authenticatable, error) {
        // validate p.UsernameOrEmail + p.Password
        // return &goauth.CredentialError on invalid creds
        return &goauth.User{ID: "user-" + p.UsernameOrEmail, Username: p.UsernameOrEmail}, nil
    }})

    // JWT bearer token strategy
    ga.RegisterStrategy(&goauth.JWTStrategy{TokenIssuer: ti})

    // Option A (overwrite allowed):
    ga.RegisterSingleton()

    // Option B (set once):
    // if err := ga.RegisterSingletonOnce(); err != nil { panic(err) }
    return ga
}
```

## Core Flows

### 1) Username/Password Login → Tokens

```go
res, access, refresh, err := ga.AuthenticateAndIssueTokens(ctx, "local", goauth.AuthParams{
    UsernameOrEmail: "alice",
    Password:        "s3cret",
})
// res.Authenticatable → user, access.Value → JWT, refresh.Value → UUID
```

### 2) Authenticate Requests with JWT

```go
res, err := ga.Authenticate(ctx, "jwt", goauth.AuthParams{Token: bearer})
// res.Authenticatable is your user; errors are typed (TokenError, etc.)
```

### 3) Refresh Tokens (Rotation)

```go
access, refresh, err := ga.RefreshToken(ctx, refreshToken)
// ValidateRefreshTokenWith determines whether it's valid and which user it belongs to
```

## HTTP Integration

Use the helpers to map typed errors to HTTP responses and error codes.

```go
func writeError(w http.ResponseWriter, err error) {
    status := goauth.HTTPStatusForError(err)
    code := goauth.ErrorCodeForError(err)
    http.Error(w, code, status)
}

func loginHandler(w http.ResponseWriter, r *http.Request, ga *goauth.GoAuth) {
    // parse JSON {"username":..., "password":...}
    ctx := r.Context()
    res, access, refresh, err := ga.AuthenticateAndIssueTokens(ctx, "local", goauth.AuthParams{
        UsernameOrEmail: r.FormValue("username"),
        Password:        r.FormValue("password"),
    })
    if err != nil {
        writeError(w, err)
        return
    }
    // marshal JSON response with user and tokens
    _ = res; _ = access; _ = refresh
}

func meHandler(w http.ResponseWriter, r *http.Request, ga *goauth.GoAuth) {
    bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
    res, err := ga.Authenticate(r.Context(), "jwt", goauth.AuthParams{Token: bearer})
    if err != nil {
        writeError(w, err)
        return
    }
    // return res.Authenticatable as JSON
    _ = res
}

func refreshHandler(w http.ResponseWriter, r *http.Request, ga *goauth.GoAuth) {
    // parse JSON {"refresh_token":...}
    access, refresh, err := ga.RefreshToken(r.Context(), r.FormValue("refresh_token"))
    if err != nil {
        writeError(w, err)
        return
    }
    // return new tokens as JSON
    _ = access; _ = refresh
}
```

## Configuration & Customization

### Token Issuer

`DefaultTokenIssuer` provides:

- `SetSecret(string)`: HS256 signing secret for access JWTs.
- `SetIssuer(string)`, `SetAudience([]string)`: standard JWT claims.
- `SetAccessTokenExpiresIn(time.Duration)`, `SetRefreshTokenExpiresIn(time.Duration)`.
- `StoreRefreshTokenWith(func)`: required; persist and rotate refresh tokens.
- `ValidateRefreshTokenWith(func)`: required; validate and resolve refresh tokens → user.
- `SetExtraClaimsWith(func)`: optional; add custom claims to access JWTs.
- `SetRegisteredClaimsWith(func)`: optional; override registered claims (exp/iss/aud/sub, etc.).
- `ConvertAccessTokenClaimsWith(func)`: optional; map claims back → user (defaults to ID/Username/Email + Extra).

If you need asymmetric signing or non-JWT tokens, implement `TokenIssuer` yourself.

### Strategies

Two built-in strategies:

- `LocalStrategy`: takes a `LookupUserWith(AuthParams) (Authenticatable, error)` function. Return `CredentialError` for bad creds, `InternalError` for DB failures, etc.
- `JWTStrategy`: takes a `TokenIssuer` and authenticates a bearer token.

Custom strategies can implement `Strategy` and be registered on `GoAuth`:

```go
type OAuthStrategy struct{}
func (s *OAuthStrategy) Name() string { return "oauth" }
func (s *OAuthStrategy) Authenticate(ctx context.Context, params goauth.AuthParams) (goauth.Authenticatable, error) {
    // exchange code → user; return typed errors as appropriate
    return &goauth.User{ID: "..."}, nil
}
ga.RegisterStrategy(&OAuthStrategy{})
```

#### Passing extra parameters

`AuthParams` includes an `Extra map[string]any` field so you can pass provider- or flow-specific values without changing the interface. Examples:

- OAuth/OIDC: `{ "provider": "google", "code_verifier": "...", "redirect_uri": "...", "state": "..." }`
- SSO/SAML: `{ "relay_state": "..." }`
- Any custom metadata you want strategies to see.

Access it in your strategy or lookup function via `params.Extra["key"]`. Prefer checking presence and type-asserting to avoid panics.

### Singleton Access

Singleton registration exists to provide an easy way to access the GoAuth instance from middleware/handlers without threading it through parameters. Use it when DI isn't practical; otherwise prefer explicit dependency injection.

If you prefer a global instance:

```go
ga := setup()
ga.RegisterSingleton()              // or: _ = ga.RegisterSingletonOnce()
// Later in handlers/services:
ga = goauth.GetInstance()
```

Testing support:

```go
restore := goauth.ReplaceSingletonForTest(mockGA)
defer restore()
```

### Typed Errors

This package returns categorized errors so you can branch behavior and log appropriately:

- `CredentialError`: bad or missing credentials.
- `TokenError`: invalid/missing/expired token, or refresh token rejected.
- `ConfigError`: misconfiguration, missing token issuer or hooks.
- `NotFoundError`: strategy not found, etc.
- `InternalError`: unexpected failure (IO/DB/crypto).

Helpers:

- `HTTPStatusForError(error) int` and `ErrorCodeForError(error) string`.
- Sentinels for common cases: `ErrMissingToken`, `ErrInvalidToken`, `ErrExpiredToken`, `ErrStrategyNotFound`, `ErrTokenIssuerUnset`.

### Refresh Token Storage (example)

```go
// Redis-like pseudo code
ti.StoreRefreshTokenWith(func(ctx context.Context, a goauth.Authenticatable, t *goauth.Token, refreshing bool) error {
    key := "rt:" + a.GetID()
    if refreshing {
        // rotate: overwrite previous token for this user
    }
    // SET key t.Value EX t.ExpiresIn
    return nil
})

ti.ValidateRefreshTokenWith(func(ctx context.Context, token string) (goauth.Authenticatable, error) {
    // GET userID by reverse index or scan keys if you store per-user
    // If not found → return &goauth.TokenError{Msg: "refresh token not found"}
    return &goauth.User{ID: "user-123"}, nil
})
```

## Security Notes

- Use a strong, rotated HS256 secret. Keep it out of source control.
- Set correct `issuer` and `audience` and validate them on consumers.
- Keep access tokens short-lived; rely on refresh tokens and rotation.
- Revoke refresh tokens on logout and on suspicious activity.
- Consider binding refresh tokens to device/session identifiers.

## Testing

- Use `errors.As(err, *TokenError)` etc. to assert failure categories.
- Stub `StoreRefreshTokenWith`/`ValidateRefreshTokenWith` to simulate rotation and revocation.
- For JWTs, set short expirations in tests and validate expiry paths.

## Example

There is a complete runnable example under `example/`:

```
go run ./example
```

It demonstrates: local login, JWT request authentication, refresh rotation.

## License

MIT
