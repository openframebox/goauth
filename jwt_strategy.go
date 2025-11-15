package goauth

import (
	"context"
	"fmt"
)

type JWTStrategy struct {
	TokenIssuer TokenIssuer
}

func (ls *JWTStrategy) Name() string {
	return "jwt"
}

func (ls *JWTStrategy) Authenticate(ctx context.Context, params AuthParams) (Authenticatable, error) {
	token := params.Token
	if token == "" {
		return nil, fmt.Errorf("token is required")
	}

	claims, err := ls.TokenIssuer.DecodeAccessToken(ctx, token)
	if err != nil {
		return nil, err
	}
	user, err := ls.TokenIssuer.ConvertAccessTokenClaims(ctx, claims)
	if err != nil {
		return nil, err
	}

	return user, nil
}
