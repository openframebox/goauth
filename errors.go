package goauth

import "fmt"

// CredentialError indicates a problem with user-provided credentials
// such as invalid username/password.
type CredentialError struct {
	Msg string
	Err error
}

func (e *CredentialError) Error() string {
	if e.Msg != "" {
		return e.Msg
	}
	if e.Err != nil {
		return e.Err.Error()
	}
	return "credential error"
}

func (e *CredentialError) Unwrap() error { return e.Err }

// TokenError indicates problems related to tokens (missing/invalid/expired).
type TokenError struct {
	Msg string
	Err error
}

func (e *TokenError) Error() string {
	if e.Msg != "" {
		return e.Msg
	}
	if e.Err != nil {
		return e.Err.Error()
	}
	return "token error"
}

func (e *TokenError) Unwrap() error { return e.Err }

// ConfigError indicates misconfiguration or missing required setup.
type ConfigError struct {
	Msg string
	Err error
}

func (e *ConfigError) Error() string {
	if e.Msg != "" {
		return e.Msg
	}
	if e.Err != nil {
		return e.Err.Error()
	}
	return "configuration error"
}

func (e *ConfigError) Unwrap() error { return e.Err }

// NotFoundError indicates a required element was not found (e.g., strategy).
type NotFoundError struct {
	Msg string
	Err error
}

func (e *NotFoundError) Error() string {
	if e.Msg != "" {
		return e.Msg
	}
	if e.Err != nil {
		return e.Err.Error()
	}
	return "not found"
}

func (e *NotFoundError) Unwrap() error { return e.Err }

// InternalError indicates an unexpected internal failure (e.g., IO/DB/signing).
type InternalError struct {
	Msg string
	Err error
}

func (e *InternalError) Error() string {
	if e.Msg != "" {
		return e.Msg
	}
	if e.Err != nil {
		return e.Err.Error()
	}
	return "internal error"
}

func (e *InternalError) Unwrap() error { return e.Err }

// Helper constructors
func NewCredentialError(msg string, err error) error { return &CredentialError{Msg: msg, Err: err} }
func NewTokenError(msg string, err error) error      { return &TokenError{Msg: msg, Err: err} }
func NewConfigError(msg string, err error) error     { return &ConfigError{Msg: msg, Err: err} }
func NewNotFoundError(msg string, err error) error   { return &NotFoundError{Msg: msg, Err: err} }
func NewInternalError(msg string, err error) error   { return &InternalError{Msg: msg, Err: err} }

// Convenience sentinels for common cases (use errors.As to match by type).
var (
	ErrInvalidCredentials = &CredentialError{Msg: "invalid credentials"}
	ErrMissingToken       = &TokenError{Msg: "token is required"}
	ErrInvalidToken       = &TokenError{Msg: "invalid token"}
	ErrExpiredToken       = &TokenError{Msg: "expired token"}
	ErrStrategyNotFound   = &NotFoundError{Msg: "strategy not found"}
	ErrTokenIssuerUnset   = &ConfigError{Msg: "token issuer is not set"}
)

// Formatting helpers to attach context without losing type info.
func withContext(err error, format string, args ...any) error {
	if err == nil {
		return nil
	}
	switch e := err.(type) {
	case *CredentialError:
		return &CredentialError{Msg: fmt.Sprintf(format, args...), Err: e}
	case *TokenError:
		return &TokenError{Msg: fmt.Sprintf(format, args...), Err: e}
	case *ConfigError:
		return &ConfigError{Msg: fmt.Sprintf(format, args...), Err: e}
	case *NotFoundError:
		return &NotFoundError{Msg: fmt.Sprintf(format, args...), Err: e}
	case *InternalError:
		return &InternalError{Msg: fmt.Sprintf(format, args...), Err: e}
	default:
		// Unknown error type -> wrap as InternalError
		return &InternalError{Msg: fmt.Sprintf(format, args...), Err: err}
	}
}
