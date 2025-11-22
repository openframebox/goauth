package goauth

import (
	"fmt"
	"time"
)

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

// RateLimitError indicates that rate limit has been exceeded.
type RateLimitError struct {
	Msg        string
	RetryAfter time.Duration
	Err        error
}

func (e *RateLimitError) Error() string {
	if e.Msg != "" {
		return e.Msg
	}
	if e.Err != nil {
		return e.Err.Error()
	}
	return "rate limit exceeded"
}

func (e *RateLimitError) Unwrap() error { return e.Err }

// ValidationError indicates validation failure on input parameters.
type ValidationError struct {
	Msg    string
	Fields map[string]string // field name -> error message
	Err    error
}

func (e *ValidationError) Error() string {
	if e.Msg != "" {
		return e.Msg
	}
	if e.Err != nil {
		return e.Err.Error()
	}
	return "validation error"
}

func (e *ValidationError) Unwrap() error { return e.Err }

// GetFieldError returns the error message for a specific field
func (e *ValidationError) GetFieldError(field string) (string, bool) {
	if e.Fields == nil {
		return "", false
	}
	msg, ok := e.Fields[field]
	return msg, ok
}

// SessionError indicates session-related problems.
type SessionError struct {
	Msg       string
	SessionID string
	Err       error
}

func (e *SessionError) Error() string {
	if e.Msg != "" {
		return e.Msg
	}
	if e.Err != nil {
		return e.Err.Error()
	}
	return "session error"
}

func (e *SessionError) Unwrap() error { return e.Err }

// Helper constructors
func NewCredentialError(msg string, err error) error { return &CredentialError{Msg: msg, Err: err} }
func NewTokenError(msg string, err error) error      { return &TokenError{Msg: msg, Err: err} }
func NewConfigError(msg string, err error) error     { return &ConfigError{Msg: msg, Err: err} }
func NewNotFoundError(msg string, err error) error   { return &NotFoundError{Msg: msg, Err: err} }
func NewInternalError(msg string, err error) error   { return &InternalError{Msg: msg, Err: err} }

func NewRateLimitError(msg string, retryAfter time.Duration) error {
	return &RateLimitError{Msg: msg, RetryAfter: retryAfter}
}

func NewValidationError(msg string, fields map[string]string) error {
	return &ValidationError{Msg: msg, Fields: fields}
}

func NewSessionError(msg string, sessionID string, err error) error {
	return &SessionError{Msg: msg, SessionID: sessionID, Err: err}
}

// Convenience sentinels for common cases (use errors.As to match by type).
var (
	// Credential errors
	ErrInvalidCredentials = &CredentialError{Msg: "invalid credentials"}
	ErrUserNotFound       = &CredentialError{Msg: "user not found"}

	// Token errors
	ErrMissingToken  = &TokenError{Msg: "token is required"}
	ErrInvalidToken  = &TokenError{Msg: "invalid token"}
	ErrExpiredToken  = &TokenError{Msg: "expired token"}
	ErrTokenRevoked  = &TokenError{Msg: "token has been revoked"}
	ErrTokenTypeMismatch = &TokenError{Msg: "unexpected token type"}

	// Config errors
	ErrTokenIssuerUnset    = &ConfigError{Msg: "token issuer is not set"}
	ErrKeyProviderUnset    = &ConfigError{Msg: "key provider is not set"}
	ErrSessionStoreUnset   = &ConfigError{Msg: "session store is not set"}

	// Not found errors
	ErrStrategyNotFound = &NotFoundError{Msg: "strategy not found"}
	ErrSessionNotFound  = &NotFoundError{Msg: "session not found"}

	// Rate limit errors
	ErrRateLimitExceeded = &RateLimitError{Msg: "rate limit exceeded"}
)

// WithContext attaches context to an error without losing type info.
// Exported for use by strategies and other packages.
func WithContext(err error, format string, args ...any) error {
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
	case *RateLimitError:
		return &RateLimitError{Msg: fmt.Sprintf(format, args...), RetryAfter: e.RetryAfter, Err: e}
	case *ValidationError:
		return &ValidationError{Msg: fmt.Sprintf(format, args...), Fields: e.Fields, Err: e}
	case *SessionError:
		return &SessionError{Msg: fmt.Sprintf(format, args...), SessionID: e.SessionID, Err: e}
	default:
		// Unknown error type -> wrap as InternalError
		return &InternalError{Msg: fmt.Sprintf(format, args...), Err: err}
	}
}

// withContext is kept for backward compatibility (unexported version)
func withContext(err error, format string, args ...any) error {
	return WithContext(err, format, args...)
}
