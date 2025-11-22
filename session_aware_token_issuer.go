package goauth

import (
	"context"
	"crypto/rsa"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// Session storage callback function types

// StoreSessionFunc stores a session and its refresh token
// oldToken is the previous refresh token being rotated (nil for initial login)
type StoreSessionFunc func(ctx context.Context, auth Authenticatable, session *SessionInfo, token *Token, oldToken *string) error

// ValidateSessionFunc validates a refresh token and returns the user and session
type ValidateSessionFunc func(ctx context.Context, token string) (Authenticatable, *SessionInfo, error)

// RevokeSessionFunc revokes a specific session
type RevokeSessionFunc func(ctx context.Context, auth Authenticatable, sessionID string) error

// RevokeAllSessionsFunc revokes all sessions for a user
type RevokeAllSessionsFunc func(ctx context.Context, auth Authenticatable) error

// ListSessionsFunc lists all active sessions for a user
type ListSessionsFunc func(ctx context.Context, auth Authenticatable) ([]*SessionInfo, error)

// GetSessionFunc gets session info by refresh token
type GetSessionFunc func(ctx context.Context, token string) (*SessionInfo, error)

// GenerateSessionIDFunc generates a unique session ID
type GenerateSessionIDFunc func(ctx context.Context) string

// ExtractSessionMetadataFunc extracts session metadata from context (device, IP, etc.)
type ExtractSessionMetadataFunc func(ctx context.Context) map[string]any

// SessionTokenIssuer implements TokenIssuer and SessionAwareTokenIssuer interfaces
// with full multi-session support and configurable signing methods
type SessionTokenIssuer struct {
	keyProvider          KeyProvider
	issuer               string
	audience             []string
	accessTokenTTL       time.Duration
	refreshTokenTTL      time.Duration

	// Session storage callbacks
	storeSession         StoreSessionFunc
	validateSession      ValidateSessionFunc
	revokeSession        RevokeSessionFunc
	revokeAllSessions    RevokeAllSessionsFunc
	listSessions         ListSessionsFunc
	getSession           GetSessionFunc

	// Optional customization callbacks
	setExtraClaims       SetExtraClaimsFunc
	setRegisteredClaims  SetRegisteredClaimsFunc
	convertClaims        ConvertAccessTokenClaimsFunc
	generateSessionID    GenerateSessionIDFunc
	extractSessionMeta   ExtractSessionMetadataFunc
}

// SessionTokenIssuerBuilder provides a fluent API for building SessionTokenIssuer
type SessionTokenIssuerBuilder struct {
	issuer *SessionTokenIssuer
	errors []error
}

// NewSessionAwareTokenIssuer creates a new builder for SessionTokenIssuer
func NewSessionAwareTokenIssuer() *SessionTokenIssuerBuilder {
	return &SessionTokenIssuerBuilder{
		issuer: &SessionTokenIssuer{
			issuer:          "goauth",
			audience:        []string{"goauth"},
			accessTokenTTL:  5 * time.Minute,
			refreshTokenTTL: 7 * 24 * time.Hour, // 7 days default for sessions
			generateSessionID: func(ctx context.Context) string {
				return uuid.New().String()
			},
		},
	}
}

// WithHMACSecret configures HMAC signing with the given secret
func (b *SessionTokenIssuerBuilder) WithHMACSecret(secret []byte, method SigningMethod) *SessionTokenIssuerBuilder {
	kp, err := NewHMACKeyProvider(secret, method)
	if err != nil {
		b.errors = append(b.errors, err)
		return b
	}
	b.issuer.keyProvider = kp
	return b
}

// WithRSAKeys configures RSA signing with the given keys
func (b *SessionTokenIssuerBuilder) WithRSAKeys(privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey, method SigningMethod) *SessionTokenIssuerBuilder {
	kp, err := NewRSAKeyProvider(privateKey, publicKey, method)
	if err != nil {
		b.errors = append(b.errors, err)
		return b
	}
	b.issuer.keyProvider = kp
	return b
}

// WithKeyProvider sets a custom key provider
func (b *SessionTokenIssuerBuilder) WithKeyProvider(kp KeyProvider) *SessionTokenIssuerBuilder {
	b.issuer.keyProvider = kp
	return b
}

// WithIssuer sets the JWT issuer claim
func (b *SessionTokenIssuerBuilder) WithIssuer(issuer string) *SessionTokenIssuerBuilder {
	b.issuer.issuer = issuer
	return b
}

// WithAudience sets the JWT audience claim
func (b *SessionTokenIssuerBuilder) WithAudience(audience []string) *SessionTokenIssuerBuilder {
	b.issuer.audience = audience
	return b
}

// WithAccessTokenTTL sets the access token time-to-live
func (b *SessionTokenIssuerBuilder) WithAccessTokenTTL(ttl time.Duration) *SessionTokenIssuerBuilder {
	b.issuer.accessTokenTTL = ttl
	return b
}

// WithRefreshTokenTTL sets the refresh token time-to-live
func (b *SessionTokenIssuerBuilder) WithRefreshTokenTTL(ttl time.Duration) *SessionTokenIssuerBuilder {
	b.issuer.refreshTokenTTL = ttl
	return b
}

// WithSessionStore sets the session storage callbacks
func (b *SessionTokenIssuerBuilder) WithSessionStore(
	store StoreSessionFunc,
	validate ValidateSessionFunc,
	revoke RevokeSessionFunc,
	revokeAll RevokeAllSessionsFunc,
) *SessionTokenIssuerBuilder {
	b.issuer.storeSession = store
	b.issuer.validateSession = validate
	b.issuer.revokeSession = revoke
	b.issuer.revokeAllSessions = revokeAll
	return b
}

// WithListSessions sets the list sessions callback
func (b *SessionTokenIssuerBuilder) WithListSessions(fn ListSessionsFunc) *SessionTokenIssuerBuilder {
	b.issuer.listSessions = fn
	return b
}

// WithGetSession sets the get session callback
func (b *SessionTokenIssuerBuilder) WithGetSession(fn GetSessionFunc) *SessionTokenIssuerBuilder {
	b.issuer.getSession = fn
	return b
}

// WithExtraClaims sets the extra claims callback
func (b *SessionTokenIssuerBuilder) WithExtraClaims(fn SetExtraClaimsFunc) *SessionTokenIssuerBuilder {
	b.issuer.setExtraClaims = fn
	return b
}

// WithRegisteredClaims sets the registered claims callback
func (b *SessionTokenIssuerBuilder) WithRegisteredClaims(fn SetRegisteredClaimsFunc) *SessionTokenIssuerBuilder {
	b.issuer.setRegisteredClaims = fn
	return b
}

// WithClaimsConverter sets the claims to Authenticatable converter
func (b *SessionTokenIssuerBuilder) WithClaimsConverter(fn ConvertAccessTokenClaimsFunc) *SessionTokenIssuerBuilder {
	b.issuer.convertClaims = fn
	return b
}

// WithSessionIDGenerator sets a custom session ID generator
func (b *SessionTokenIssuerBuilder) WithSessionIDGenerator(fn GenerateSessionIDFunc) *SessionTokenIssuerBuilder {
	b.issuer.generateSessionID = fn
	return b
}

// WithSessionMetadataExtractor sets a custom session metadata extractor
func (b *SessionTokenIssuerBuilder) WithSessionMetadataExtractor(fn ExtractSessionMetadataFunc) *SessionTokenIssuerBuilder {
	b.issuer.extractSessionMeta = fn
	return b
}

// Build creates the SessionTokenIssuer, returning any configuration errors
func (b *SessionTokenIssuerBuilder) Build() (*SessionTokenIssuer, error) {
	if len(b.errors) > 0 {
		return nil, b.errors[0]
	}

	if b.issuer.keyProvider == nil {
		return nil, ErrKeyProviderUnset
	}

	if b.issuer.storeSession == nil || b.issuer.validateSession == nil {
		return nil, ErrSessionStoreUnset
	}

	return b.issuer, nil
}

// CreateAccessToken creates a new JWT access token with session ID
func (ti *SessionTokenIssuer) CreateAccessToken(ctx context.Context, auth Authenticatable) (*Token, error) {
	return ti.CreateAccessTokenWithSession(ctx, auth, "")
}

// CreateAccessTokenWithSession creates a new JWT access token with a specific session ID
func (ti *SessionTokenIssuer) CreateAccessTokenWithSession(ctx context.Context, auth Authenticatable, sessionID string) (*Token, error) {
	if ti.keyProvider == nil {
		return nil, ErrKeyProviderUnset
	}

	extraClaims := make(map[string]any)
	if ti.setExtraClaims != nil {
		extraClaims = ti.setExtraClaims(ctx, auth)
	}

	now := time.Now()
	var registeredClaims jwt.RegisteredClaims
	if ti.setRegisteredClaims != nil {
		registeredClaims = ti.setRegisteredClaims(ctx, auth)
	} else {
		registeredClaims = jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(ti.accessTokenTTL)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			Subject:   auth.GetID(),
			Issuer:    ti.issuer,
			Audience:  ti.audience,
		}
	}

	claims := TokenClaims{
		RegisteredClaims: registeredClaims,
		Username:         auth.GetUsername(),
		Email:            auth.GetEmail(),
		TokenType:        AccessToken,
		SessionID:        sessionID,
		ExtraClaims:      extraClaims,
	}

	token := jwt.NewWithClaims(ti.keyProvider.Method(), claims)
	tokenString, err := token.SignedString(ti.keyProvider.SignKey())
	if err != nil {
		return nil, &InternalError{Msg: "failed to sign access token", Err: err}
	}

	return &Token{
		Value:     tokenString,
		Type:      AccessToken,
		ExpiresIn: ti.accessTokenTTL,
		IssuedAt:  now,
		SessionID: sessionID,
	}, nil
}

// CreateRefreshToken creates a new refresh token with session
func (ti *SessionTokenIssuer) CreateRefreshToken(ctx context.Context, auth Authenticatable, oldToken *string) (*Token, error) {
	if ti.storeSession == nil {
		return nil, ErrSessionStoreUnset
	}

	now := time.Now()

	// Generate session ID - reuse from old token if rotating, otherwise generate new
	var sessionID string
	if oldToken != nil && ti.getSession != nil {
		oldSession, err := ti.getSession(ctx, *oldToken)
		if err == nil && oldSession != nil {
			sessionID = oldSession.ID
		}
	}
	if sessionID == "" {
		sessionID = ti.generateSessionID(ctx)
	}

	// Extract session metadata from context
	var metadata map[string]any
	if ti.extractSessionMeta != nil {
		metadata = ti.extractSessionMeta(ctx)
	}

	session := &SessionInfo{
		ID:        sessionID,
		UserID:    auth.GetID(),
		CreatedAt: now,
		ExpiresAt: now.Add(ti.refreshTokenTTL),
		Metadata:  metadata,
	}

	tokenString := uuid.New().String()
	token := &Token{
		Value:     tokenString,
		Type:      RefreshToken,
		ExpiresIn: ti.refreshTokenTTL,
		IssuedAt:  now,
		SessionID: sessionID,
	}

	err := ti.storeSession(ctx, auth, session, token, oldToken)
	if err != nil {
		return nil, &InternalError{Msg: "failed to store session", Err: err}
	}

	return token, nil
}

// DecodeAccessToken parses and validates a JWT access token
func (ti *SessionTokenIssuer) DecodeAccessToken(ctx context.Context, tokenStr string) (*TokenClaims, error) {
	if ti.keyProvider == nil {
		return nil, ErrKeyProviderUnset
	}

	parsedToken, err := jwt.ParseWithClaims(tokenStr, &TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Verify the signing method matches
		if token.Method.Alg() != ti.keyProvider.Method().Alg() {
			return nil, &TokenError{Msg: "unexpected signing method"}
		}
		return ti.keyProvider.VerifyKey(), nil
	})

	if err != nil {
		return nil, &TokenError{Msg: "failed to parse or validate access token", Err: err}
	}

	claims, ok := parsedToken.Claims.(*TokenClaims)
	if !ok {
		return nil, &TokenError{Msg: "invalid token claims"}
	}

	return claims, nil
}

// ConvertAccessTokenClaims converts token claims to an Authenticatable entity
func (ti *SessionTokenIssuer) ConvertAccessTokenClaims(ctx context.Context, claims *TokenClaims) (Authenticatable, error) {
	if ti.convertClaims != nil {
		a, err := ti.convertClaims(ctx, claims)
		if err != nil {
			return nil, &TokenError{Msg: "failed to convert access token claims", Err: err}
		}
		return a, nil
	}

	return &User{
		ID:       claims.Subject,
		Username: claims.Username,
		Email:    claims.Email,
		Extra:    claims.ExtraClaims,
	}, nil
}

// ValidateRefreshToken validates a refresh token and returns the associated user
func (ti *SessionTokenIssuer) ValidateRefreshToken(ctx context.Context, token string) (Authenticatable, error) {
	if ti.validateSession == nil {
		return nil, ErrSessionStoreUnset
	}

	auth, _, err := ti.validateSession(ctx, token)
	if err != nil {
		return nil, &TokenError{Msg: "invalid or rejected refresh token", Err: err}
	}

	return auth, nil
}

// RevokeRefreshToken revokes a refresh token by revoking its session
func (ti *SessionTokenIssuer) RevokeRefreshToken(ctx context.Context, token string) error {
	if ti.getSession == nil || ti.revokeSession == nil {
		return ErrSessionStoreUnset
	}

	session, err := ti.getSession(ctx, token)
	if err != nil {
		return &TokenError{Msg: "failed to get session for token", Err: err}
	}

	// We need to get the user to revoke the session
	auth, _, err := ti.validateSession(ctx, token)
	if err != nil {
		return &TokenError{Msg: "failed to validate token for revocation", Err: err}
	}

	return ti.revokeSession(ctx, auth, session.ID)
}

// GetSession returns session information for a refresh token
func (ti *SessionTokenIssuer) GetSession(ctx context.Context, token string) (*SessionInfo, error) {
	if ti.getSession == nil {
		return nil, ErrSessionStoreUnset
	}

	session, err := ti.getSession(ctx, token)
	if err != nil {
		return nil, &TokenError{Msg: "failed to get session", Err: err}
	}

	return session, nil
}

// RevokeSession revokes a specific session by ID
func (ti *SessionTokenIssuer) RevokeSession(ctx context.Context, auth Authenticatable, sessionID string) error {
	if ti.revokeSession == nil {
		return ErrSessionStoreUnset
	}

	err := ti.revokeSession(ctx, auth, sessionID)
	if err != nil {
		return &SessionError{Msg: "failed to revoke session", SessionID: sessionID, Err: err}
	}

	return nil
}

// RevokeAllSessions revokes all sessions for an authenticated entity
func (ti *SessionTokenIssuer) RevokeAllSessions(ctx context.Context, auth Authenticatable) error {
	if ti.revokeAllSessions == nil {
		return ErrSessionStoreUnset
	}

	err := ti.revokeAllSessions(ctx, auth)
	if err != nil {
		return &InternalError{Msg: "failed to revoke all sessions", Err: err}
	}

	return nil
}

// ListSessions returns all active sessions for an authenticated entity
func (ti *SessionTokenIssuer) ListSessions(ctx context.Context, auth Authenticatable) ([]*SessionInfo, error) {
	if ti.listSessions == nil {
		return nil, ErrSessionStoreUnset
	}

	sessions, err := ti.listSessions(ctx, auth)
	if err != nil {
		return nil, &InternalError{Msg: "failed to list sessions", Err: err}
	}

	return sessions, nil
}

// IssueTokenPair creates both access and refresh tokens in one call
// This is a convenience method that ensures tokens share the same session ID
func (ti *SessionTokenIssuer) IssueTokenPair(ctx context.Context, auth Authenticatable, oldRefreshToken *string) (*TokenPair, error) {
	refreshToken, err := ti.CreateRefreshToken(ctx, auth, oldRefreshToken)
	if err != nil {
		return nil, err
	}

	accessToken, err := ti.CreateAccessTokenWithSession(ctx, auth, refreshToken.SessionID)
	if err != nil {
		return nil, err
	}

	return &TokenPair{
		Access:  accessToken,
		Refresh: refreshToken,
	}, nil
}
