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
	CreateRefreshToken(ctx context.Context, authenticatable Authenticatable) (*Token, error)
	DecodeAccessToken(ctx context.Context, token string) (*TokenClaims, error)
	ConvertTokenClaims(ctx context.Context, claims *TokenClaims) (Authenticatable, error)
}
