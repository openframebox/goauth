# goauth

[![Go Reference](https://pkg.go.dev/badge/github.com/openframebox/goauth/v2.svg)](https://pkg.go.dev/github.com/openframebox/goauth/v2)

Pluggable authentication for Go. Build username/password or JWT-based auth with a simple strategy interface, configurable JWT access/refresh token issuers with multi-session support, and typed errors for clean, predictable error handling.

Works as an auth core you can drop into HTTP APIs, gRPC, or CLIs.

## Version

**Current: v2.0.0**

This is a major version with breaking changes from v1. See [Migration from v1](#migration-from-v1) for upgrade guide.

## Installation

```bash
go get github.com/openframebox/goauth/v2
```

For v1 (legacy):

```bash
go get github.com/openframebox/goauth
```

## Features

- **Multi-session support** - Users can have multiple active sessions (e.g., phone + laptop)
- **Token rotation** - Proper refresh token rotation with old token invalidation
- **Multiple signing algorithms** - HS256/384/512, RS256/384/512, ES256/384/512
- **Event hooks** - `OnBeforeAuthenticate`, `OnAfterAuthenticate`, `OnTokenIssued`, `OnTokenRevoked`
- **Rate limiting** - Built-in interfaces for rate limiting strategies
- **Password validation** - Optional bcrypt/argon2 integration
- **Thread-safe** - Safe for concurrent use
- **Typed errors** - Categorized errors for consistent HTTP responses

## Concepts

- **Strategy**: pluggable auth mechanism (Local, JWT, OAuth, SSO). Implement `Name()` and `Authenticate()`.
- **Authenticatable**: minimal user interface (`GetID`, `GetUsername`, `GetEmail`, `GetExtra`).
- **TokenIssuer**: creates/verifies access tokens and manages refresh tokens.
  - `DefaultTokenIssuer`: basic HS256 JWT issuer
  - `SessionTokenIssuer`: multi-session aware issuer with configurable signing
- **SessionInfo**: session metadata (ID, device, IP, expiry) for multi-session support
- **Typed Errors**: `CredentialError`, `TokenError`, `ConfigError`, `NotFoundError`, `InternalError`, `RateLimitError`, `ValidationError`, `SessionError`

## Quick Start

```
go run ./example                    # Basic multi-session demo
go run ./example/http_server        # HTTP server example
```

## Basic Setup (DefaultTokenIssuer)

For simple use cases without multi-session support:

```go
package main

import (
    "context"
    goauth "github.com/openframebox/goauth/v2"
)

func setup() *goauth.GoAuth {
    // Configure token issuer
    ti := goauth.NewDefaultTokenIssuer("supersecret")
    ti.SetIssuer("api.example.com")
    ti.SetAudience([]string{"api.example.com"})

    // Required: refresh token storage
    ti.StoreRefreshTokenWith(func(ctx context.Context, a goauth.Authenticatable, tok *goauth.Token, oldToken *string) error {
        // oldToken is nil for initial login, non-nil for refresh (rotation)
        if oldToken != nil {
            // Invalidate the old token
        }
        // Store tok.Value with user a.GetID()
        return nil
    })

    ti.ValidateRefreshTokenWith(func(ctx context.Context, token string) (goauth.Authenticatable, error) {
        // Lookup token -> user; return error if invalid
        return &goauth.User{ID: "user-123"}, nil
    })

    ti.RevokeRefreshTokenWith(func(ctx context.Context, token string) error {
        // Delete the token from storage
        return nil
    })

    // Build orchestrator
    ga := goauth.New()
    ga.SetTokenIssuer(ti)

    // Register strategies using builder pattern
    ga.RegisterStrategy(goauth.NewLocalStrategy(func(ctx context.Context, p goauth.AuthParams) (goauth.Authenticatable, error) {
        // Validate credentials
        return &goauth.User{ID: "user-" + p.UsernameOrEmail, Username: p.UsernameOrEmail}, nil
    }))

    ga.RegisterStrategy(goauth.NewJWTStrategy(ti).WithExpectedType(goauth.AccessToken))

    return ga
}
```

## Multi-Session Setup (SessionTokenIssuer)

For apps that need multi-device login, session management, and advanced signing:

```go
package main

import (
    "context"
    "time"
    goauth "github.com/openframebox/goauth/v2"
)

func setup() *goauth.GoAuth {
    // Create key provider (supports HS256/384/512, RS256/384/512, ES256/384/512)
    keyProvider, _ := goauth.NewHMACKeyProvider([]byte("supersecret"), goauth.HS256)

    // Build session-aware token issuer
    issuer, _ := goauth.NewSessionAwareTokenIssuer().
        WithKeyProvider(keyProvider).
        WithIssuer("api.example.com").
        WithAudience([]string{"api.example.com"}).
        WithAccessTokenTTL(15 * time.Minute).
        WithRefreshTokenTTL(7 * 24 * time.Hour).
        WithSessionStore(
            storeSession,      // Store session + token
            validateSession,   // Validate token -> user + session
            revokeSession,     // Revoke single session
            revokeAllSessions, // Revoke all user sessions
        ).
        WithListSessions(listSessions).
        WithGetSession(getSession).
        WithSessionMetadataExtractor(func(ctx context.Context) map[string]any {
            // Extract device info, IP, user agent from context
            return map[string]any{"device": "browser", "ip": "127.0.0.1"}
        }).
        Build()

    ga := goauth.New()
    ga.SetTokenIssuer(issuer)

    // Register strategies
    ga.RegisterStrategy(goauth.NewLocalStrategy(lookupUser))
    ga.RegisterStrategy(goauth.NewJWTStrategy(issuer).WithExpectedType(goauth.AccessToken))

    return ga
}

// Session store callbacks
func storeSession(ctx context.Context, auth goauth.Authenticatable, session *goauth.SessionInfo, token *goauth.Token, oldToken *string) error {
    // If oldToken != nil, invalidate it (rotation)
    // Store session with token
    return nil
}

func validateSession(ctx context.Context, token string) (goauth.Authenticatable, *goauth.SessionInfo, error) {
    // Lookup token -> user + session
    return user, session, nil
}

func revokeSession(ctx context.Context, auth goauth.Authenticatable, sessionID string) error {
    // Delete session by ID
    return nil
}

func revokeAllSessions(ctx context.Context, auth goauth.Authenticatable) error {
    // Delete all sessions for user
    return nil
}

func listSessions(ctx context.Context, auth goauth.Authenticatable) ([]*goauth.SessionInfo, error) {
    // Return all active sessions for user
    return sessions, nil
}

func getSession(ctx context.Context, token string) (*goauth.SessionInfo, error) {
    // Get session info by token
    return session, nil
}
```

## Choosing a Token Issuer

| Feature                 | DefaultTokenIssuer   | SessionTokenIssuer                                   |
| ----------------------- | -------------------- | ---------------------------------------------------- |
| **Signing algorithms**  | HS256 only           | HS256/384/512, RS256/384/512, ES256/384/512          |
| **Multi-device login**  | No session isolation | Each device = unique session                         |
| **Session management**  | None                 | `ListSessions`, `RevokeSession`, `RevokeAllSessions` |
| **JWT `sid` claim**     | Not included         | Session ID embedded in access token                  |
| **Session metadata**    | None                 | Device, IP, user agent tracking                      |
| **Configuration style** | Setter methods       | Builder pattern                                      |
| **Storage callbacks**   | Token-centric        | Session-centric                                      |

**Use `DefaultTokenIssuer` when:**

- Simple single-session apps
- You only need basic JWT with HS256
- You manage token storage yourself without session semantics

**Use `SessionTokenIssuer` when:**

- Users log in from multiple devices (phone + laptop)
- You need "see all active sessions" or "logout all devices" features
- You want flexible signing algorithms (RSA, ECDSA)
- You need session metadata (device info, IP tracking)

## Core Flows

### 1) Login and Issue Tokens

```go
// Returns individual tokens
res, access, refresh, err := ga.AuthenticateAndIssueTokens(ctx, "local", goauth.AuthParams{
    UsernameOrEmail: "alice",
    Password:        "s3cret",
})

// Or returns TokenPair
res, pair, err := ga.AuthenticateAndIssueTokenPair(ctx, "local", params)
// pair.Access, pair.Refresh, pair.Access.SessionID
```

### 2) Authenticate Requests with JWT

```go
res, err := ga.Authenticate(ctx, "jwt", goauth.AuthParams{Token: bearer})
// res.Authenticatable is your user
```

### 3) Refresh Tokens (with rotation)

```go
// Old refresh token is passed to storage for invalidation
pair, err := ga.RefreshTokenPair(ctx, refreshToken)
// pair.Access (new), pair.Refresh (new, old is invalidated)
```

### 4) Revoke Tokens / Sessions

```go
// Revoke single token
err := ga.RevokeToken(ctx, refreshToken)

// Revoke specific session (requires SessionTokenIssuer)
err := ga.RevokeSession(ctx, user, sessionID)

// Revoke all sessions (logout everywhere)
err := ga.RevokeAllTokens(ctx, user)
```

### 5) List Active Sessions

```go
sessions, err := ga.ListSessions(ctx, user)
for _, s := range sessions {
    fmt.Printf("Session %s: device=%s, expires=%s\n",
        s.ID, s.Metadata["device"], s.ExpiresAt)
}
```

## Event Hooks

Add logging, audit trails, or custom logic:

```go
type MyHooks struct {
    goauth.NoOpEventHooks // Embed to only override what you need
}

func (h *MyHooks) OnBeforeAuthenticate(ctx context.Context, strategy string, params goauth.AuthParams) error {
    // Rate limiting, logging, etc.
    // Return error to block authentication
    return nil
}

func (h *MyHooks) OnAfterAuthenticate(ctx context.Context, strategy string, result *goauth.AuthResult, err error) {
    if err != nil {
        log.Printf("Auth failed for strategy %s: %v", strategy, err)
    } else {
        log.Printf("User %s authenticated via %s", result.Authenticatable.GetID(), strategy)
    }
}

func (h *MyHooks) OnTokenIssued(ctx context.Context, auth goauth.Authenticatable, tokens *goauth.TokenPair) {
    log.Printf("Tokens issued for user %s, session %s", auth.GetID(), tokens.Access.SessionID)
}

func (h *MyHooks) OnTokenRevoked(ctx context.Context, auth goauth.Authenticatable, token string) {
    log.Printf("Token revoked for user %s", auth.GetID())
}

// Register hooks
ga.SetEventHooks(&MyHooks{})
```

## Strategy Enhancements

### LocalStrategy with Password Validation & Rate Limiting

```go
strategy := goauth.NewLocalStrategy(lookupUser).
    WithName("local").
    WithPasswordValidator(
        func(plain, hashed string) bool {
            return bcrypt.CompareHashAndPassword([]byte(hashed), []byte(plain)) == nil
        },
        func(user goauth.Authenticatable) string {
            return user.(*MyUser).HashedPassword
        },
    ).
    WithRateLimiter(
        func(ctx context.Context, identifier string) error {
            // Return goauth.ErrRateLimitExceeded if blocked
            return nil
        },
        func(ctx context.Context, identifier string, success bool) {
            // Record attempt for rate limiting
        },
    ).
    WithUsernameNormalizer(func(username string) string {
        return strings.ToLower(strings.TrimSpace(username))
    })
```

### JWTStrategy with Token Type & Revocation Check

```go
strategy := goauth.NewJWTStrategy(issuer).
    WithName("jwt").
    WithExpectedType(goauth.AccessToken).  // Reject refresh tokens
    WithRevocationCheck(func(ctx context.Context, token string) bool {
        // Return true if token is revoked
        return isRevoked(token)
    })
```

## Signing Algorithms

```go
// HMAC (symmetric)
kp, _ := goauth.NewHMACKeyProvider([]byte("secret"), goauth.HS256)
kp, _ := goauth.NewHMACKeyProvider([]byte("secret"), goauth.HS384)
kp, _ := goauth.NewHMACKeyProvider([]byte("secret"), goauth.HS512)

// RSA (asymmetric)
kp, _ := goauth.NewRSAKeyProvider(privateKey, publicKey, goauth.RS256)

// ECDSA (asymmetric)
kp, _ := goauth.NewECDSAKeyProvider(privateKey, publicKey, goauth.ES256)
```

## HTTP Integration

```go
func loginHandler(w http.ResponseWriter, r *http.Request) {
    var req LoginRequest
    json.NewDecoder(r.Body).Decode(&req)

    _, pair, err := ga.AuthenticateAndIssueTokenPair(r.Context(), "local", goauth.AuthParams{
        UsernameOrEmail: req.Username,
        Password:        req.Password,
    })
    if err != nil {
        resp := goauth.ErrorResponseForError(err)
        w.WriteHeader(resp.Status)
        json.NewEncoder(w).Encode(resp)
        return
    }

    json.NewEncoder(w).Encode(map[string]any{
        "access_token":  pair.Access.Value,
        "refresh_token": pair.Refresh.Value,
        "expires_in":    int(pair.Access.ExpiresIn.Seconds()),
        "session_id":    pair.Access.SessionID,
    })
}

func authMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
        result, err := ga.Authenticate(r.Context(), "jwt", goauth.AuthParams{Token: token})
        if err != nil {
            resp := goauth.ErrorResponseForError(err)
            w.WriteHeader(resp.Status)
            json.NewEncoder(w).Encode(resp)
            return
        }
        ctx := context.WithValue(r.Context(), "user", result.Authenticatable)
        next.ServeHTTP(w, r.WithContext(ctx))
    })
}
```

## Error Types & HTTP Mapping

| Error Type        | HTTP Status | Error Code                                                                            |
| ----------------- | ----------- | ------------------------------------------------------------------------------------- |
| `CredentialError` | 401         | `invalid_credentials`                                                                 |
| `TokenError`      | 401         | `token_error` / `token_missing` / `token_invalid` / `token_expired` / `token_revoked` |
| `ValidationError` | 400         | `validation_error`                                                                    |
| `RateLimitError`  | 429         | `rate_limit_exceeded`                                                                 |
| `NotFoundError`   | 404         | `not_found` / `strategy_not_found` / `session_not_found`                              |
| `ConfigError`     | 500         | `config_error`                                                                        |
| `InternalError`   | 500         | `internal_error`                                                                      |
| `SessionError`    | 401         | `session_error`                                                                       |

```go
// Get structured error response
resp := goauth.ErrorResponseForError(err)
// resp.Status, resp.Code, resp.Message, resp.Fields (for validation), resp.RetryAfter (for rate limit)

// Or individual helpers
status := goauth.HTTPStatusForError(err)
code := goauth.ErrorCodeForError(err)
retryAfter := goauth.RetryAfterForError(err)
```

## Thread Safety

`GoAuth` is safe for concurrent use:

```go
// Strategy registration is mutex-protected
ga.RegisterStrategy(strategy)
ga.UnregisterStrategy("oauth")
ga.HasStrategy("local")
ga.ListStrategies()
```

## Singleton Access

For convenience when DI isn't practical:

```go
ga.RegisterSingleton()              // Overwrite allowed
_ = ga.RegisterSingletonOnce()      // Set once, error on second

// Later
ga = goauth.GetInstance()

// Testing
restore := goauth.ReplaceSingletonForTest(mockGA)
defer restore()
```

## Examples

```bash
# Multi-session demo
go run ./example

# HTTP server with login, refresh, logout, sessions endpoints
go run ./example/http_server
```

The HTTP server example provides:

- `POST /login` - Authenticate and get tokens
- `POST /refresh` - Refresh tokens
- `POST /logout` - Revoke current session
- `POST /logout-all` - Revoke all sessions
- `GET /me` - Get current user (protected)
- `GET /sessions` - List active sessions (protected)

## Migration from v1

### Breaking Changes

1. **Module path changed**: Import path is now `github.com/openframebox/goauth/v2`

   ```go
   // v1
   import goauth "github.com/openframebox/goauth"
   // v2
   import goauth "github.com/openframebox/goauth/v2"
   ```

2. **TokenIssuer interface**: `CreateRefreshToken` signature changed

   ```go
   // v1
   CreateRefreshToken(ctx, auth, refreshing bool) (*Token, error)
   // v2
   CreateRefreshToken(ctx, auth, oldToken *string) (*Token, error)
   ```

3. **StoreRefreshTokenFunc**: signature changed

   ```go
   // v1
   func(ctx, auth, token, refreshing bool) error
   // v2
   func(ctx, auth, token, oldToken *string) error
   ```

4. **Strategy constructors**: use builder pattern

   ```go
   // v1
   &goauth.LocalStrategy{LookupUserWith: fn}
   // v2
   goauth.NewLocalStrategy(fn)

   // v1
   &goauth.JWTStrategy{TokenIssuer: ti}
   // v2
   goauth.NewJWTStrategy(ti)
   ```

5. **Token struct**: new fields added

   - `Type` (TokenType) - "access" or "refresh"
   - `IssuedAt` (time.Time)
   - `SessionID` (string)

6. **New required method on TokenIssuer**: `RevokeRefreshToken(ctx, token string) error`

7. **GoAuth methods**: New `TokenPair` returning methods added
   - `IssueTokenPair()` alongside `IssueTokens()`
   - `RefreshTokenPair()` alongside `RefreshToken()`
   - `AuthenticateAndIssueTokenPair()` alongside `AuthenticateAndIssueTokens()`

### New Features in v2

- **Multi-session support** with `SessionTokenIssuer`
- **Multiple signing algorithms** (HS256/384/512, RS256/384/512, ES256/384/512)
- **Event hooks** (`AuthEventHooks` interface)
- **Rate limiting support** in strategies
- **Password validation** in `LocalStrategy`
- **Token type validation** in `JWTStrategy`
- **Thread-safe** strategy registration with `sync.RWMutex`
- **New error types**: `RateLimitError`, `ValidationError`, `SessionError`
- **Session management**: `ListSessions`, `RevokeSession`, `RevokeAllTokens`

## Security Notes

- Use strong, rotated secrets. Keep them out of source control.
- Set correct `issuer` and `audience` claims.
- Keep access tokens short-lived (5-15 min).
- Implement proper refresh token rotation.
- Revoke tokens on logout and suspicious activity.
- Use rate limiting on authentication endpoints.
- Hash passwords with bcrypt/argon2.

## License

MIT
