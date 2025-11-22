package goauth

import (
	"context"
)

// CheckRevokedFunc checks if a token has been revoked
type CheckRevokedFunc func(ctx context.Context, token string) bool

// ConvertClaimsFunc converts token claims to an Authenticatable
type ConvertClaimsFunc func(ctx context.Context, claims *TokenClaims) (Authenticatable, error)

// JWTStrategy implements JWT token-based authentication
type JWTStrategy struct {
	name          string
	tokenIssuer   TokenIssuer
	expectedType  TokenType      // Optional: validate token type
	checkRevoked  CheckRevokedFunc
	convertClaims ConvertClaimsFunc
}

// NewJWTStrategy creates a new JWTStrategy with the given token issuer
func NewJWTStrategy(tokenIssuer TokenIssuer) *JWTStrategy {
	return &JWTStrategy{
		name:        "jwt",
		tokenIssuer: tokenIssuer,
	}
}

// WithName sets a custom name for the strategy
func (js *JWTStrategy) WithName(name string) *JWTStrategy {
	js.name = name
	return js
}

// WithExpectedType sets the expected token type
// When set, the strategy will reject tokens that don't match
func (js *JWTStrategy) WithExpectedType(tokenType TokenType) *JWTStrategy {
	js.expectedType = tokenType
	return js
}

// WithRevocationCheck sets the revocation check function
func (js *JWTStrategy) WithRevocationCheck(check CheckRevokedFunc) *JWTStrategy {
	js.checkRevoked = check
	return js
}

// WithClaimsConverter sets a custom claims to Authenticatable converter
// This overrides the TokenIssuer's ConvertAccessTokenClaims
func (js *JWTStrategy) WithClaimsConverter(convert ConvertClaimsFunc) *JWTStrategy {
	js.convertClaims = convert
	return js
}

// Name returns the strategy name
func (js *JWTStrategy) Name() string {
	return js.name
}

// Authenticate authenticates using a JWT token
func (js *JWTStrategy) Authenticate(ctx context.Context, params AuthParams) (Authenticatable, error) {
	token := params.Token
	if token == "" {
		return nil, ErrMissingToken
	}

	// Check if token is revoked
	if js.checkRevoked != nil && js.checkRevoked(ctx, token) {
		return nil, ErrTokenRevoked
	}

	// Decode and validate token
	claims, err := js.tokenIssuer.DecodeAccessToken(ctx, token)
	if err != nil {
		return nil, WithContext(err, "failed to decode access token")
	}

	// Validate token type if expected type is set
	if js.expectedType != "" && claims.TokenType != js.expectedType {
		// Special case: empty token type is treated as access token (backward compatibility)
		if !(js.expectedType == AccessToken && claims.TokenType == "") {
			return nil, ErrTokenTypeMismatch
		}
	}

	// Convert claims to user
	var user Authenticatable
	if js.convertClaims != nil {
		user, err = js.convertClaims(ctx, claims)
	} else {
		user, err = js.tokenIssuer.ConvertAccessTokenClaims(ctx, claims)
	}

	if err != nil {
		return nil, WithContext(err, "failed to convert token claims")
	}

	return user, nil
}

// GetTokenIssuer returns the underlying token issuer
// Deprecated: Access TokenIssuer directly
func (js *JWTStrategy) GetTokenIssuer() TokenIssuer {
	return js.tokenIssuer
}

// SetTokenIssuer sets the token issuer (for backward compatibility)
// Deprecated: Use NewJWTStrategy instead
func (js *JWTStrategy) SetTokenIssuer(ti TokenIssuer) {
	js.tokenIssuer = ti
}
