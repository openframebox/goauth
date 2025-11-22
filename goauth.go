package goauth

import (
	"context"
	"fmt"
	"sync"
)

// GoAuth is the main orchestrator for authentication and token management
type GoAuth struct {
	tokenIssuer TokenIssuer
	strategies  map[string]Strategy
	hooks       AuthEventHooks
	mu          sync.RWMutex
}

// New creates a new GoAuth instance
func New() *GoAuth {
	ga := &GoAuth{
		strategies: make(map[string]Strategy),
	}
	return ga
}

// RegisterStrategy registers an authentication strategy
// If a strategy with the same name already exists, it will not be replaced
func (ga *GoAuth) RegisterStrategy(strategy Strategy) {
	ga.mu.Lock()
	defer ga.mu.Unlock()

	if _, ok := ga.strategies[strategy.Name()]; !ok {
		ga.strategies[strategy.Name()] = strategy
	}
}

// UnregisterStrategy removes a registered strategy by name
func (ga *GoAuth) UnregisterStrategy(name string) error {
	ga.mu.Lock()
	defer ga.mu.Unlock()

	if _, ok := ga.strategies[name]; !ok {
		return &NotFoundError{Msg: fmt.Sprintf("strategy %s not found", name)}
	}

	delete(ga.strategies, name)
	return nil
}

// HasStrategy checks if a strategy is registered
func (ga *GoAuth) HasStrategy(name string) bool {
	ga.mu.RLock()
	defer ga.mu.RUnlock()

	_, ok := ga.strategies[name]
	return ok
}

// ListStrategies returns the names of all registered strategies
func (ga *GoAuth) ListStrategies() []string {
	ga.mu.RLock()
	defer ga.mu.RUnlock()

	names := make([]string, 0, len(ga.strategies))
	for name := range ga.strategies {
		names = append(names, name)
	}
	return names
}

// SetTokenIssuer sets the token issuer for the GoAuth instance
func (ga *GoAuth) SetTokenIssuer(tokenIssuer TokenIssuer) {
	ga.tokenIssuer = tokenIssuer
}

// GetTokenIssuer returns the current token issuer
func (ga *GoAuth) GetTokenIssuer() TokenIssuer {
	return ga.tokenIssuer
}

// SetEventHooks sets the event hooks for authentication events
func (ga *GoAuth) SetEventHooks(hooks AuthEventHooks) {
	ga.hooks = hooks
}

// Authenticate authenticates using the specified strategy
func (ga *GoAuth) Authenticate(ctx context.Context, strategy string, params AuthParams) (*AuthResult, error) {
	// Call before hook
	if ga.hooks != nil {
		if err := ga.hooks.OnBeforeAuthenticate(ctx, strategy, params); err != nil {
			return nil, err
		}
	}

	s, err := ga.lookupStrategy(strategy)
	if err != nil {
		if ga.hooks != nil {
			ga.hooks.OnAfterAuthenticate(ctx, strategy, nil, err)
		}
		return nil, err
	}

	user, err := s.Authenticate(ctx, params)
	if err != nil {
		if ga.hooks != nil {
			ga.hooks.OnAfterAuthenticate(ctx, strategy, nil, err)
		}
		return nil, err
	}

	result := &AuthResult{
		Authenticatable: user,
		Strategy:        s.Name(),
	}

	// Call after hook
	if ga.hooks != nil {
		ga.hooks.OnAfterAuthenticate(ctx, strategy, result, nil)
	}

	return result, nil
}

// IssueTokens creates access and refresh tokens for an authenticated entity
// Returns individual tokens (for backward compatibility)
func (ga *GoAuth) IssueTokens(ctx context.Context, authenticatable Authenticatable) (accessToken *Token, refreshToken *Token, err error) {
	pair, err := ga.IssueTokenPair(ctx, authenticatable)
	if err != nil {
		return nil, nil, err
	}
	return pair.Access, pair.Refresh, nil
}

// IssueTokenPair creates access and refresh tokens as a TokenPair
func (ga *GoAuth) IssueTokenPair(ctx context.Context, authenticatable Authenticatable) (*TokenPair, error) {
	if ga.tokenIssuer == nil {
		return nil, ErrTokenIssuerUnset
	}

	accessToken, err := ga.tokenIssuer.CreateAccessToken(ctx, authenticatable)
	if err != nil {
		return nil, err
	}

	refreshToken, err := ga.tokenIssuer.CreateRefreshToken(ctx, authenticatable, nil)
	if err != nil {
		return nil, err
	}

	pair := &TokenPair{
		Access:  accessToken,
		Refresh: refreshToken,
	}

	// Call token issued hook
	if ga.hooks != nil {
		ga.hooks.OnTokenIssued(ctx, authenticatable, pair)
	}

	return pair, nil
}

// AuthenticateAndIssueTokens authenticates and issues tokens in one call
// Returns individual tokens (for backward compatibility)
func (ga *GoAuth) AuthenticateAndIssueTokens(ctx context.Context, strategy string, params AuthParams) (authResult *AuthResult, accessToken *Token, refreshToken *Token, err error) {
	result, pair, err := ga.AuthenticateAndIssueTokenPair(ctx, strategy, params)
	if err != nil {
		return nil, nil, nil, err
	}
	return result, pair.Access, pair.Refresh, nil
}

// AuthenticateAndIssueTokenPair authenticates and issues tokens as a TokenPair
func (ga *GoAuth) AuthenticateAndIssueTokenPair(ctx context.Context, strategy string, params AuthParams) (*AuthResult, *TokenPair, error) {
	result, err := ga.Authenticate(ctx, strategy, params)
	if err != nil {
		return nil, nil, err
	}

	pair, err := ga.IssueTokenPair(ctx, result.Authenticatable)
	if err != nil {
		return nil, nil, err
	}

	return result, pair, nil
}

// RefreshToken validates the old refresh token and issues new tokens
// Returns individual tokens (for backward compatibility)
func (ga *GoAuth) RefreshToken(ctx context.Context, token string) (accessToken *Token, refreshToken *Token, err error) {
	pair, err := ga.RefreshTokenPair(ctx, token)
	if err != nil {
		return nil, nil, err
	}
	return pair.Access, pair.Refresh, nil
}

// RefreshTokenPair validates the old refresh token and issues new tokens as a TokenPair
func (ga *GoAuth) RefreshTokenPair(ctx context.Context, token string) (*TokenPair, error) {
	if ga.tokenIssuer == nil {
		return nil, ErrTokenIssuerUnset
	}

	user, err := ga.tokenIssuer.ValidateRefreshToken(ctx, token)
	if err != nil {
		return nil, err
	}

	if user == nil {
		return nil, &TokenError{Msg: "invalid refresh token"}
	}

	accessToken, err := ga.tokenIssuer.CreateAccessToken(ctx, user)
	if err != nil {
		return nil, err
	}

	// Pass the old token for proper rotation
	refreshToken, err := ga.tokenIssuer.CreateRefreshToken(ctx, user, &token)
	if err != nil {
		return nil, err
	}

	pair := &TokenPair{
		Access:  accessToken,
		Refresh: refreshToken,
	}

	// Call token issued hook
	if ga.hooks != nil {
		ga.hooks.OnTokenIssued(ctx, user, pair)
	}

	return pair, nil
}

// RevokeToken revokes a refresh token
func (ga *GoAuth) RevokeToken(ctx context.Context, token string) error {
	if ga.tokenIssuer == nil {
		return ErrTokenIssuerUnset
	}

	// Get user before revoking for the hook
	var user Authenticatable
	if ga.hooks != nil {
		user, _ = ga.tokenIssuer.ValidateRefreshToken(ctx, token)
	}

	err := ga.tokenIssuer.RevokeRefreshToken(ctx, token)
	if err != nil {
		return err
	}

	// Call token revoked hook
	if ga.hooks != nil && user != nil {
		ga.hooks.OnTokenRevoked(ctx, user, token)
	}

	return nil
}

// RevokeAllTokens revokes all sessions for an authenticated entity
// Only works if the token issuer implements SessionAwareTokenIssuer
func (ga *GoAuth) RevokeAllTokens(ctx context.Context, authenticatable Authenticatable) error {
	if ga.tokenIssuer == nil {
		return ErrTokenIssuerUnset
	}

	sessionIssuer, ok := ga.tokenIssuer.(SessionAwareTokenIssuer)
	if !ok {
		return &ConfigError{Msg: "token issuer does not support session management"}
	}

	return sessionIssuer.RevokeAllSessions(ctx, authenticatable)
}

// ListSessions lists all active sessions for an authenticated entity
// Only works if the token issuer implements SessionAwareTokenIssuer
func (ga *GoAuth) ListSessions(ctx context.Context, authenticatable Authenticatable) ([]*SessionInfo, error) {
	if ga.tokenIssuer == nil {
		return nil, ErrTokenIssuerUnset
	}

	sessionIssuer, ok := ga.tokenIssuer.(SessionAwareTokenIssuer)
	if !ok {
		return nil, &ConfigError{Msg: "token issuer does not support session management"}
	}

	return sessionIssuer.ListSessions(ctx, authenticatable)
}

// RevokeSession revokes a specific session by ID
// Only works if the token issuer implements SessionAwareTokenIssuer
func (ga *GoAuth) RevokeSession(ctx context.Context, authenticatable Authenticatable, sessionID string) error {
	if ga.tokenIssuer == nil {
		return ErrTokenIssuerUnset
	}

	sessionIssuer, ok := ga.tokenIssuer.(SessionAwareTokenIssuer)
	if !ok {
		return &ConfigError{Msg: "token issuer does not support session management"}
	}

	err := sessionIssuer.RevokeSession(ctx, authenticatable, sessionID)
	if err != nil {
		return err
	}

	// Call session revoked hook
	if ga.hooks != nil {
		ga.hooks.OnSessionRevoked(ctx, authenticatable, &SessionInfo{ID: sessionID})
	}

	return nil
}

// lookupStrategy finds a strategy by name (thread-safe)
func (ga *GoAuth) lookupStrategy(name string) (Strategy, error) {
	ga.mu.RLock()
	defer ga.mu.RUnlock()

	if strategy, ok := ga.strategies[name]; ok {
		return strategy, nil
	}
	return nil, &NotFoundError{Msg: fmt.Sprintf("strategy %s not found", name)}
}
