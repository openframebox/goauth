package goauth

import (
	"context"
)

// Strategy defines the authentication strategy interface
type Strategy interface {
	Name() string
	Authenticate(ctx context.Context, params AuthParams) (Authenticatable, error)
}

// Authenticatable represents an authenticated entity (user, service, etc.)
type Authenticatable interface {
	GetID() string
	GetUsername() string
	GetEmail() string
	GetExtra() map[string]any
}

// TokenIssuer defines the contract for token creation and validation
type TokenIssuer interface {
	// CreateAccessToken generates a new access token for the authenticated entity
	CreateAccessToken(ctx context.Context, authenticatable Authenticatable) (*Token, error)

	// CreateRefreshToken generates a new refresh token
	// oldToken is the previous refresh token being rotated (nil for initial login)
	CreateRefreshToken(ctx context.Context, authenticatable Authenticatable, oldToken *string) (*Token, error)

	// DecodeAccessToken parses and validates an access token, returning its claims
	DecodeAccessToken(ctx context.Context, token string) (*TokenClaims, error)

	// ConvertAccessTokenClaims converts token claims back to an Authenticatable entity
	ConvertAccessTokenClaims(ctx context.Context, claims *TokenClaims) (Authenticatable, error)

	// ValidateRefreshToken validates a refresh token and returns the associated entity
	ValidateRefreshToken(ctx context.Context, token string) (Authenticatable, error)

	// RevokeRefreshToken invalidates a refresh token
	RevokeRefreshToken(ctx context.Context, token string) error
}

// SessionAwareTokenIssuer extends TokenIssuer with session management capabilities
type SessionAwareTokenIssuer interface {
	TokenIssuer

	// GetSession returns session information for a refresh token
	GetSession(ctx context.Context, token string) (*SessionInfo, error)

	// RevokeSession revokes a specific session by ID
	RevokeSession(ctx context.Context, authenticatable Authenticatable, sessionID string) error

	// RevokeAllSessions revokes all sessions for an authenticated entity
	RevokeAllSessions(ctx context.Context, authenticatable Authenticatable) error

	// ListSessions returns all active sessions for an authenticated entity
	ListSessions(ctx context.Context, authenticatable Authenticatable) ([]*SessionInfo, error)
}

// AuthEventHooks provides hooks for authentication events
// Implement this interface to add custom logic (logging, audit, rate limiting, etc.)
type AuthEventHooks interface {
	// OnBeforeAuthenticate is called before authentication
	// Return an error to prevent authentication (e.g., rate limiting)
	OnBeforeAuthenticate(ctx context.Context, strategy string, params AuthParams) error

	// OnAfterAuthenticate is called after authentication (success or failure)
	OnAfterAuthenticate(ctx context.Context, strategy string, result *AuthResult, err error)

	// OnTokenIssued is called when tokens are issued
	OnTokenIssued(ctx context.Context, authenticatable Authenticatable, tokens *TokenPair)

	// OnTokenRevoked is called when a token is revoked
	OnTokenRevoked(ctx context.Context, authenticatable Authenticatable, token string)

	// OnSessionCreated is called when a new session is created
	OnSessionCreated(ctx context.Context, authenticatable Authenticatable, session *SessionInfo)

	// OnSessionRevoked is called when a session is revoked
	OnSessionRevoked(ctx context.Context, authenticatable Authenticatable, session *SessionInfo)
}

// NoOpEventHooks is a default implementation of AuthEventHooks that does nothing
// Embed this in your custom hooks to only override the methods you need
type NoOpEventHooks struct{}

func (h *NoOpEventHooks) OnBeforeAuthenticate(ctx context.Context, strategy string, params AuthParams) error {
	return nil
}

func (h *NoOpEventHooks) OnAfterAuthenticate(ctx context.Context, strategy string, result *AuthResult, err error) {
}

func (h *NoOpEventHooks) OnTokenIssued(ctx context.Context, authenticatable Authenticatable, tokens *TokenPair) {
}

func (h *NoOpEventHooks) OnTokenRevoked(ctx context.Context, authenticatable Authenticatable, token string) {
}

func (h *NoOpEventHooks) OnSessionCreated(ctx context.Context, authenticatable Authenticatable, session *SessionInfo) {
}

func (h *NoOpEventHooks) OnSessionRevoked(ctx context.Context, authenticatable Authenticatable, session *SessionInfo) {
}

// PasswordValidator defines the contract for password validation
type PasswordValidator interface {
	// ValidatePassword checks if the plain password matches the hashed password
	ValidatePassword(plain, hashed string) bool
}

// PasswordValidatorFunc is a function adapter for PasswordValidator
type PasswordValidatorFunc func(plain, hashed string) bool

func (f PasswordValidatorFunc) ValidatePassword(plain, hashed string) bool {
	return f(plain, hashed)
}

// RateLimiter defines the contract for rate limiting authentication attempts
type RateLimiter interface {
	// CheckRateLimit checks if the authentication attempt is allowed
	// Returns nil if allowed, RateLimitError if exceeded
	CheckRateLimit(ctx context.Context, identifier string) error

	// RecordAttempt records an authentication attempt (success or failure)
	RecordAttempt(ctx context.Context, identifier string, success bool)
}

// TokenRevoker defines the contract for checking token revocation
type TokenRevoker interface {
	// IsRevoked checks if a token has been revoked
	IsRevoked(ctx context.Context, token string) bool

	// Revoke marks a token as revoked
	Revoke(ctx context.Context, token string) error
}
