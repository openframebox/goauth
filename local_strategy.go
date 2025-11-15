package goauth

import "context"

type LookupUserFunc func(params AuthParams) (Authenticatable, error)

type LocalStrategy struct {
	LookupUserWith LookupUserFunc
}

func (ls *LocalStrategy) Name() string {
	return "local"
}

func (ls *LocalStrategy) Authenticate(ctx context.Context, params AuthParams) (Authenticatable, error) {
	user, err := ls.LookupUserWith(params)
	if err != nil {
		return nil, err
	}

	return user, nil
}
