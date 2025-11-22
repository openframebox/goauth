package goauth

import (
	"context"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// Callback function types for DefaultTokenIssuer

// StoreRefreshTokenFunc stores a refresh token
// oldToken is the previous refresh token being rotated (nil for initial login)
type StoreRefreshTokenFunc func(ctx context.Context, authenticatable Authenticatable, token *Token, oldToken *string) error

// SetExtraClaimsFunc returns extra claims to include in the access token
type SetExtraClaimsFunc func(ctx context.Context, authenticatable Authenticatable) map[string]any

// SetRegisteredClaimsFunc returns custom registered claims for the access token
type SetRegisteredClaimsFunc func(ctx context.Context, authenticatable Authenticatable) jwt.RegisteredClaims

// ConvertAccessTokenClaimsFunc converts token claims to an Authenticatable entity
type ConvertAccessTokenClaimsFunc func(ctx context.Context, claims *TokenClaims) (Authenticatable, error)

// ValidateRefreshTokenFunc validates a refresh token and returns the associated user
type ValidateRefreshTokenFunc func(ctx context.Context, token string) (Authenticatable, error)

// RevokeRefreshTokenFunc revokes a refresh token
type RevokeRefreshTokenFunc func(ctx context.Context, token string) error

// DefaultTokenIssuer is a basic implementation of TokenIssuer
// For multi-session support, use SessionAwareTokenIssuer instead
type DefaultTokenIssuer struct {
	secret                       string
	issuer                       string
	audience                     []string
	accessTokenExpiresIn         time.Duration
	refreshTokenExpiresIn        time.Duration
	storeRefreshTokenWith        StoreRefreshTokenFunc
	setExtraClaimsWith           SetExtraClaimsFunc
	setRegisteredClaimsWith      SetRegisteredClaimsFunc
	convertAccessTokenClaimsWith ConvertAccessTokenClaimsFunc
	validateRefreshTokenWith     ValidateRefreshTokenFunc
	revokeRefreshTokenWith       RevokeRefreshTokenFunc
}

// NewDefaultTokenIssuer creates a new DefaultTokenIssuer with sensible defaults
func NewDefaultTokenIssuer(secret string) *DefaultTokenIssuer {
	ti := &DefaultTokenIssuer{
		secret:                secret,
		issuer:                "goauth",
		audience:              []string{"goauth"},
		accessTokenExpiresIn:  300 * time.Second,  // default 5 minutes
		refreshTokenExpiresIn: 3600 * time.Second, // default 1 hour
	}

	return ti
}

// SetSecret sets the JWT signing secret
func (ti *DefaultTokenIssuer) SetSecret(secret string) {
	ti.secret = secret
}

// SetIssuer sets the JWT issuer claim
func (ti *DefaultTokenIssuer) SetIssuer(issuer string) {
	ti.issuer = issuer
}

// SetAudience sets the JWT audience claim
func (ti *DefaultTokenIssuer) SetAudience(audience []string) {
	ti.audience = audience
}

// SetAccessTokenExpiresIn sets the access token expiration duration
func (ti *DefaultTokenIssuer) SetAccessTokenExpiresIn(expiresIn time.Duration) {
	ti.accessTokenExpiresIn = expiresIn
}

// SetRefreshTokenExpiresIn sets the refresh token expiration duration
func (ti *DefaultTokenIssuer) SetRefreshTokenExpiresIn(expiresIn time.Duration) {
	ti.refreshTokenExpiresIn = expiresIn
}

// StoreRefreshTokenWith sets the callback for storing refresh tokens
func (ti *DefaultTokenIssuer) StoreRefreshTokenWith(storeRefreshTokenWith StoreRefreshTokenFunc) {
	ti.storeRefreshTokenWith = storeRefreshTokenWith
}

// SetExtraClaimsWith sets the callback for adding extra claims to access tokens
func (ti *DefaultTokenIssuer) SetExtraClaimsWith(setExtraClaimsWith SetExtraClaimsFunc) {
	ti.setExtraClaimsWith = setExtraClaimsWith
}

// SetRegisteredClaimsWith sets the callback for customizing registered claims
func (ti *DefaultTokenIssuer) SetRegisteredClaimsWith(setRegisteredClaimsWith SetRegisteredClaimsFunc) {
	ti.setRegisteredClaimsWith = setRegisteredClaimsWith
}

// ConvertAccessTokenClaimsWith sets the callback for converting claims to Authenticatable
func (ti *DefaultTokenIssuer) ConvertAccessTokenClaimsWith(convertAccessTokenClaimsWith ConvertAccessTokenClaimsFunc) {
	ti.convertAccessTokenClaimsWith = convertAccessTokenClaimsWith
}

// ValidateRefreshTokenWith sets the callback for validating refresh tokens
func (ti *DefaultTokenIssuer) ValidateRefreshTokenWith(validateRefreshTokenWith ValidateRefreshTokenFunc) {
	ti.validateRefreshTokenWith = validateRefreshTokenWith
}

// RevokeRefreshTokenWith sets the callback for revoking refresh tokens
func (ti *DefaultTokenIssuer) RevokeRefreshTokenWith(revokeRefreshTokenWith RevokeRefreshTokenFunc) {
	ti.revokeRefreshTokenWith = revokeRefreshTokenWith
}

// CreateAccessToken creates a new JWT access token
func (ti *DefaultTokenIssuer) CreateAccessToken(ctx context.Context, authenticatable Authenticatable) (*Token, error) {
	extraClaims := make(map[string]any)
	if ti.setExtraClaimsWith != nil {
		extraClaims = ti.setExtraClaimsWith(ctx, authenticatable)
	}

	now := time.Now()
	var registeredClaims jwt.RegisteredClaims
	if ti.setRegisteredClaimsWith != nil {
		registeredClaims = ti.setRegisteredClaimsWith(ctx, authenticatable)
	} else {
		registeredClaims = jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(ti.accessTokenExpiresIn)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			Subject:   authenticatable.GetID(),
			Issuer:    ti.issuer,
			Audience:  ti.audience,
		}
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, TokenClaims{
		RegisteredClaims: registeredClaims,
		Username:         authenticatable.GetUsername(),
		Email:            authenticatable.GetEmail(),
		TokenType:        AccessToken,
		ExtraClaims:      extraClaims,
	})

	tokenString, err := token.SignedString([]byte(ti.secret))
	if err != nil {
		return nil, err
	}

	return &Token{
		Value:     tokenString,
		Type:      AccessToken,
		ExpiresIn: ti.accessTokenExpiresIn,
		IssuedAt:  now,
	}, nil
}

// CreateRefreshToken creates a new refresh token
// oldToken is the previous refresh token being rotated (nil for initial login)
func (ti *DefaultTokenIssuer) CreateRefreshToken(ctx context.Context, authenticatable Authenticatable, oldToken *string) (*Token, error) {
	if ti.storeRefreshTokenWith == nil {
		return nil, &ConfigError{Msg: "StoreRefreshTokenWith is not set"}
	}

	now := time.Now()
	tokenString := uuid.New().String()
	token := &Token{
		Value:     tokenString,
		Type:      RefreshToken,
		ExpiresIn: ti.refreshTokenExpiresIn,
		IssuedAt:  now,
	}

	err := ti.storeRefreshTokenWith(ctx, authenticatable, token, oldToken)
	if err != nil {
		return nil, &InternalError{Msg: "failed to store refresh token", Err: err}
	}

	return token, nil
}

// DecodeAccessToken parses and validates a JWT access token
func (ti *DefaultTokenIssuer) DecodeAccessToken(ctx context.Context, token string) (*TokenClaims, error) {
	parsedToken, err := jwt.ParseWithClaims(token, &TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(ti.secret), nil
	})

	if err != nil {
		// jwt lib returns various errors (validation/signature/expired). Classify as token error.
		return nil, &TokenError{Msg: "failed to parse or validate access token", Err: err}
	}

	claims, ok := parsedToken.Claims.(*TokenClaims)
	if !ok {
		return nil, &TokenError{Msg: "invalid token claims"}
	}

	return claims, nil
}

// ConvertAccessTokenClaims converts token claims to an Authenticatable entity
func (ti *DefaultTokenIssuer) ConvertAccessTokenClaims(ctx context.Context, claims *TokenClaims) (Authenticatable, error) {
	if ti.convertAccessTokenClaimsWith != nil {
		a, err := ti.convertAccessTokenClaimsWith(ctx, claims)
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
func (ti *DefaultTokenIssuer) ValidateRefreshToken(ctx context.Context, token string) (Authenticatable, error) {
	if ti.validateRefreshTokenWith == nil {
		return nil, &ConfigError{Msg: "ValidateRefreshTokenWith is not set"}
	}

	authenticatable, err := ti.validateRefreshTokenWith(ctx, token)
	if err != nil {
		return nil, &TokenError{Msg: "invalid or rejected refresh token", Err: err}
	}

	return authenticatable, nil
}

// RevokeRefreshToken revokes a refresh token
func (ti *DefaultTokenIssuer) RevokeRefreshToken(ctx context.Context, token string) error {
	if ti.revokeRefreshTokenWith == nil {
		return &ConfigError{Msg: "RevokeRefreshTokenWith is not set"}
	}

	err := ti.revokeRefreshTokenWith(ctx, token)
	if err != nil {
		return &InternalError{Msg: "failed to revoke refresh token", Err: err}
	}

	return nil
}
