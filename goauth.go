package goauth

import (
	"context"
	"fmt"
)

type GoAuth struct {
	tokenIssuer TokenIssuer
	strategies  map[string]Strategy
}

func New() *GoAuth {
	ga := &GoAuth{}
	ga.strategies = make(map[string]Strategy)

	return ga
}

func (ga *GoAuth) RegisterStrategy(strategy Strategy) {
	if _, ok := ga.strategies[strategy.Name()]; !ok {
		ga.strategies[strategy.Name()] = strategy
	}
}

func (ga *GoAuth) SetTokenIssuer(tokenIssuer TokenIssuer) {
	ga.tokenIssuer = tokenIssuer
}

func (ga *GoAuth) Authenticate(ctx context.Context, strategy string, params AuthParams) (*AuthResult, error) {
	s, err := ga.lookupStrategy(strategy)

	if err != nil {
		return nil, err
	}

	user, err := s.Authenticate(ctx, params)
	if err != nil {
		return nil, err
	}

	return &AuthResult{
		Authenticatable: user,
		Strategy:        s.Name(),
	}, nil
}

func (ga *GoAuth) IssueTokens(ctx context.Context, authenticatable Authenticatable) (accessToken *Token, refreshToken *Token, err error) {
	if ga.tokenIssuer == nil {
		return nil, nil, ErrTokenIssuerUnset
	}

	accessToken, err = ga.tokenIssuer.CreateAccessToken(ctx, authenticatable)
	if err != nil {
		return nil, nil, err
	}

	refreshToken, err = ga.tokenIssuer.CreateRefreshToken(ctx, authenticatable, false)
	if err != nil {
		return nil, nil, err
	}

	return accessToken, refreshToken, nil
}

func (ga *GoAuth) AuthenticateAndIssueTokens(ctx context.Context, strategy string, params AuthParams) (authResult *AuthResult, accessToken *Token, refreshToken *Token, err error) {
	result, err := ga.Authenticate(ctx, strategy, params)
	if err != nil {
		return nil, nil, nil, err
	}

	accessToken, refreshToken, err = ga.IssueTokens(ctx, result.Authenticatable)
	if err != nil {
		return nil, nil, nil, err
	}

	return result, accessToken, refreshToken, nil
}

func (ga *GoAuth) RefreshToken(ctx context.Context, token string) (accessToken *Token, refreshToken *Token, err error) {
	if ga.tokenIssuer == nil {
		return nil, nil, ErrTokenIssuerUnset
	}

	user, err := ga.tokenIssuer.ValidateRefreshToken(ctx, token)
	if err != nil {
		return nil, nil, err
	}

	if user == nil {
		return nil, nil, &TokenError{Msg: "invalid refresh token"}
	}

	accessToken, err = ga.tokenIssuer.CreateAccessToken(ctx, user)
	if err != nil {
		return nil, nil, err
	}

	refreshToken, err = ga.tokenIssuer.CreateRefreshToken(ctx, user, true)
	if err != nil {
		return nil, nil, err
	}

	return accessToken, refreshToken, nil
}

func (ga *GoAuth) lookupStrategy(name string) (Strategy, error) {
	if strategy, ok := ga.strategies[name]; ok {
		return strategy, nil
	} else {
		return nil, &NotFoundError{Msg: fmt.Sprintf("strategy %s not found", name)}
	}
}
