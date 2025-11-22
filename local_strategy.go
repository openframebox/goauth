package goauth

import (
	"context"
	"errors"
	"strings"
)

// LookupUserFunc looks up a user by credentials and returns an Authenticatable
// The returned user should have a hashed password available if password validation is used
type LookupUserFunc func(ctx context.Context, params AuthParams) (Authenticatable, error)

// ValidatePasswordFunc validates a plain password against a hashed password
type ValidatePasswordFunc func(plain, hashed string) bool

// RateLimitCheckFunc checks if an authentication attempt should be rate limited
// Returns nil if allowed, RateLimitError if exceeded
type RateLimitCheckFunc func(ctx context.Context, identifier string) error

// RecordAttemptFunc records an authentication attempt for rate limiting
type RecordAttemptFunc func(ctx context.Context, identifier string, success bool)

// NormalizeUsernameFunc normalizes a username (e.g., trim whitespace, lowercase)
type NormalizeUsernameFunc func(username string) string

// GetHashedPasswordFunc retrieves the hashed password from an Authenticatable
// Used when password validation is enabled
type GetHashedPasswordFunc func(user Authenticatable) string

// LocalStrategy implements username/password authentication
type LocalStrategy struct {
	name              string
	lookupUser        LookupUserFunc
	validatePassword  ValidatePasswordFunc
	getHashedPassword GetHashedPasswordFunc
	checkRateLimit    RateLimitCheckFunc
	recordAttempt     RecordAttemptFunc
	normalizeUsername NormalizeUsernameFunc
}

// NewLocalStrategy creates a new LocalStrategy with the given lookup function
func NewLocalStrategy(lookupUser LookupUserFunc) *LocalStrategy {
	return &LocalStrategy{
		name:       "local",
		lookupUser: lookupUser,
		normalizeUsername: func(username string) string {
			return strings.TrimSpace(username)
		},
	}
}

// WithName sets a custom name for the strategy
func (ls *LocalStrategy) WithName(name string) *LocalStrategy {
	ls.name = name
	return ls
}

// WithPasswordValidator sets the password validation function
// When set, the strategy will validate the password from AuthParams against
// the hashed password retrieved via GetHashedPassword
func (ls *LocalStrategy) WithPasswordValidator(validate ValidatePasswordFunc, getHashed GetHashedPasswordFunc) *LocalStrategy {
	ls.validatePassword = validate
	ls.getHashedPassword = getHashed
	return ls
}

// WithRateLimiter sets the rate limiting functions
func (ls *LocalStrategy) WithRateLimiter(check RateLimitCheckFunc, record RecordAttemptFunc) *LocalStrategy {
	ls.checkRateLimit = check
	ls.recordAttempt = record
	return ls
}

// WithUsernameNormalizer sets a custom username normalization function
func (ls *LocalStrategy) WithUsernameNormalizer(normalize NormalizeUsernameFunc) *LocalStrategy {
	ls.normalizeUsername = normalize
	return ls
}

// Name returns the strategy name
func (ls *LocalStrategy) Name() string {
	return ls.name
}

// Authenticate authenticates a user with username/email and password
func (ls *LocalStrategy) Authenticate(ctx context.Context, params AuthParams) (Authenticatable, error) {
	// Normalize username
	if ls.normalizeUsername != nil {
		params.UsernameOrEmail = ls.normalizeUsername(params.UsernameOrEmail)
	}

	// Check rate limit
	if ls.checkRateLimit != nil {
		if err := ls.checkRateLimit(ctx, params.UsernameOrEmail); err != nil {
			return nil, err
		}
	}

	// Lookup user
	user, err := ls.lookupUser(ctx, params)
	if err != nil {
		// Record failed attempt
		if ls.recordAttempt != nil {
			ls.recordAttempt(ctx, params.UsernameOrEmail, false)
		}
		return nil, forwardTypedError(err)
	}

	// Validate password if enabled
	if ls.validatePassword != nil && ls.getHashedPassword != nil {
		hashedPassword := ls.getHashedPassword(user)
		if !ls.validatePassword(params.Password, hashedPassword) {
			// Record failed attempt
			if ls.recordAttempt != nil {
				ls.recordAttempt(ctx, params.UsernameOrEmail, false)
			}
			return nil, ErrInvalidCredentials
		}
	}

	// Record successful attempt
	if ls.recordAttempt != nil {
		ls.recordAttempt(ctx, params.UsernameOrEmail, true)
	}

	return user, nil
}

// LookupUserWith is kept for backward compatibility
// Deprecated: Use NewLocalStrategy instead
func (ls *LocalStrategy) SetLookupUser(fn LookupUserFunc) {
	ls.lookupUser = fn
}

// forwardTypedError forwards known typed errors, wrapping unknown errors as InternalError
func forwardTypedError(err error) error {
	if err == nil {
		return nil
	}

	var (
		credErr *CredentialError
		tokErr  *TokenError
		cfgErr  *ConfigError
		nfErr   *NotFoundError
		intErr  *InternalError
		rlErr   *RateLimitError
		valErr  *ValidationError
		sessErr *SessionError
	)

	switch {
	case errors.As(err, &credErr):
		return credErr
	case errors.As(err, &tokErr):
		return tokErr
	case errors.As(err, &cfgErr):
		return cfgErr
	case errors.As(err, &nfErr):
		return nfErr
	case errors.As(err, &intErr):
		return intErr
	case errors.As(err, &rlErr):
		return rlErr
	case errors.As(err, &valErr):
		return valErr
	case errors.As(err, &sessErr):
		return sessErr
	default:
		// Unknown error -> treat as internal failure
		return &InternalError{Msg: "lookup user failed", Err: err}
	}
}
