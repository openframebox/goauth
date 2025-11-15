package goauth

import (
	"context"

	"github.com/golang-jwt/jwt/v5"
)

type StoreRefreshTokenFunc func(ctx context.Context, authenticatable Authenticatable, token *Token, refreshing bool) error
type SetExtraClaimsFunc func(ctx context.Context, authenticatable Authenticatable) map[string]any
type SetRegisteredClaimsFunc func(ctx context.Context, authenticatable Authenticatable) jwt.RegisteredClaims
type ConvertAccessTokenClaimsFunc func(ctx context.Context, claims *TokenClaims) (Authenticatable, error)
type ValidateRefreshTokenFunc func(ctx context.Context, token string) (Authenticatable, error)

type Strategy interface {
	Name() string
	Authenticate(ctx context.Context, params AuthParams) (Authenticatable, error)
}

type Authenticatable interface {
	GetID() string
	GetUsername() string
	GetEmail() string
	GetExtraData() map[string]any
}

type TokenIssuer interface {
	CreateAccessToken(ctx context.Context, authenticatable Authenticatable) (*Token, error)
	CreateRefreshToken(ctx context.Context, authenticatable Authenticatable, refreshing bool) (*Token, error)
	DecodeAccessToken(ctx context.Context, token string) (*TokenClaims, error)
	ConvertAccessTokenClaims(ctx context.Context, claims *TokenClaims) (Authenticatable, error)
	ValidateRefreshToken(ctx context.Context, token string) (Authenticatable, error)
}
