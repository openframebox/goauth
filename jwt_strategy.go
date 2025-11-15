package goauth

import (
	"context"
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
		return nil, &TokenError{Msg: "token is required"}
	}

	claims, err := ls.TokenIssuer.DecodeAccessToken(ctx, token)
	if err != nil {
		return nil, withContext(&TokenError{Err: err}, "failed to decode access token")
	}
	user, err := ls.TokenIssuer.ConvertAccessTokenClaims(ctx, claims)
	if err != nil {
		return nil, withContext(&TokenError{Err: err}, "failed to convert token claims")
	}

	return user, nil
}
