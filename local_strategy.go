package goauth

import (
	"context"
	"errors"
)

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
		// If the Lookup returns a known typed error, forward it.
		var (
			credErr *CredentialError
			tokErr  *TokenError
			cfgErr  *ConfigError
			nfErr   *NotFoundError
			intErr  *InternalError
		)
		switch {
		case errors.As(err, &credErr):
			return nil, credErr
		case errors.As(err, &tokErr):
			return nil, tokErr
		case errors.As(err, &cfgErr):
			return nil, cfgErr
		case errors.As(err, &nfErr):
			return nil, nfErr
		case errors.As(err, &intErr):
			return nil, intErr
		default:
			// Unknown error -> treat as internal failure
			return nil, &InternalError{Msg: "lookup user failed", Err: err}
		}
	}

	return user, nil
}
