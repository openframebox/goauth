package goauth

import "context"

type LocalStrategy struct {
	LookupUserWith (func(params AuthParams) (Authenticatable, error))
}

func (ls *LocalStrategy) Name() string {
	return "local"
}

func (ls *LocalStrategy) Authenticate(ctx context.Context, params AuthParams) (*AuthResult, error) {
	user, err := ls.LookupUserWith(params)
	if err != nil {
		return nil, err
	}

	return &AuthResult{
		Authenticatable: user,
		Strategy:        ls.Name(),
	}, nil
}
