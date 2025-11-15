package goauth

import "context"

type Strategy interface {
	Name() string
	Authenticate(ctx context.Context, params AuthParams) (*AuthResult, error)
}

type Authenticatable interface {
	GetID() string
	GetUsername() string
	GetEmail() string
	ExtraData() map[string]any
}

type TokenIssuer interface {
	CreateAccessToken(ctx context.Context, authenticatable Authenticatable) (*Token, error)
	CreateRefreshToken(ctx context.Context, authenticatable Authenticatable, refreshing bool) (*Token, error)
	DecodeAccessToken(ctx context.Context, token string) (*TokenClaims, error)
	ConvertAccessTokenClaims(ctx context.Context, claims *TokenClaims) (Authenticatable, error)
	ValidateRefreshToken(ctx context.Context, token string) (Authenticatable, error)
}
