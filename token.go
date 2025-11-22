package goauth

import (
	"github.com/golang-jwt/jwt/v5"
)

// TokenClaims represents the JWT claims for access tokens
type TokenClaims struct {
	jwt.RegisteredClaims
	Username    string         `json:"username,omitempty"`
	Email       string         `json:"email,omitempty"`
	TokenType   TokenType      `json:"typ,omitempty"` // "access" or "refresh"
	SessionID   string         `json:"sid,omitempty"` // Session identifier for multi-session support
	ExtraClaims map[string]any `json:"ext,omitempty"`
}

// GetExtraClaim returns a value from extra claims
func (tc *TokenClaims) GetExtraClaim(key string) (any, bool) {
	if tc.ExtraClaims == nil {
		return nil, false
	}
	v, ok := tc.ExtraClaims[key]
	return v, ok
}

// GetExtraClaimString returns a string value from extra claims
func (tc *TokenClaims) GetExtraClaimString(key string) (string, bool) {
	v, ok := tc.GetExtraClaim(key)
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	return s, ok
}

// GetExtraClaimBool returns a bool value from extra claims
func (tc *TokenClaims) GetExtraClaimBool(key string) (bool, bool) {
	v, ok := tc.GetExtraClaim(key)
	if !ok {
		return false, false
	}
	b, ok := v.(bool)
	return b, ok
}

// IsAccessToken returns true if this is an access token
func (tc *TokenClaims) IsAccessToken() bool {
	return tc.TokenType == AccessToken || tc.TokenType == ""
}

// IsRefreshToken returns true if this is a refresh token
func (tc *TokenClaims) IsRefreshToken() bool {
	return tc.TokenType == RefreshToken
}
