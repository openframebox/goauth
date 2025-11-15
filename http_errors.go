package goauth

import (
	"errors"
	"net/http"
)

// HTTPStatusForError maps typed goauth errors to an HTTP status code.
// Fallthrough defaults to 500 for unknown error types.
func HTTPStatusForError(err error) int {
	if err == nil {
		return http.StatusOK
	}

	// Specific sentinels first
	switch {
	case errors.Is(err, ErrMissingToken), errors.Is(err, ErrInvalidToken), errors.Is(err, ErrExpiredToken):
		return http.StatusUnauthorized
	case errors.Is(err, ErrStrategyNotFound):
		return http.StatusNotFound
	case errors.Is(err, ErrTokenIssuerUnset):
		return http.StatusInternalServerError
	}

	// Category types next
	var (
		cred *CredentialError
		tok  *TokenError
		cfg  *ConfigError
		nf   *NotFoundError
		inr  *InternalError
	)
	switch {
	case errors.As(err, &cred):
		return http.StatusUnauthorized
	case errors.As(err, &tok):
		return http.StatusUnauthorized
	case errors.As(err, &cfg):
		return http.StatusInternalServerError
	case errors.As(err, &nf):
		return http.StatusNotFound
	case errors.As(err, &inr):
		return http.StatusInternalServerError
	default:
		return http.StatusInternalServerError
	}
}

// ErrorCodeForError returns a stable, client-facing error code string.
// Use alongside HTTPStatusForError to build consistent error responses.
func ErrorCodeForError(err error) string {
	if err == nil {
		return "ok"
	}

	// Specific sentinels first
	switch {
	case errors.Is(err, ErrMissingToken):
		return "token_missing"
	case errors.Is(err, ErrInvalidToken):
		return "token_invalid"
	case errors.Is(err, ErrExpiredToken):
		return "token_expired"
	case errors.Is(err, ErrStrategyNotFound):
		return "strategy_not_found"
	case errors.Is(err, ErrTokenIssuerUnset):
		return "config_token_issuer_unset"
	}

	// Category types next
	var (
		cred *CredentialError
		tok  *TokenError
		cfg  *ConfigError
		nf   *NotFoundError
		inr  *InternalError
	)
	switch {
	case errors.As(err, &cred):
		return "invalid_credentials"
	case errors.As(err, &tok):
		return "token_error"
	case errors.As(err, &cfg):
		return "config_error"
	case errors.As(err, &nf):
		return "not_found"
	case errors.As(err, &inr):
		return "internal_error"
	default:
		return "internal_error"
	}
}
