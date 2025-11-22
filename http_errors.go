package goauth

import (
	"errors"
	"net/http"
	"time"
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
	case errors.Is(err, ErrTokenRevoked):
		return http.StatusUnauthorized
	case errors.Is(err, ErrTokenTypeMismatch):
		return http.StatusUnauthorized
	case errors.Is(err, ErrStrategyNotFound):
		return http.StatusNotFound
	case errors.Is(err, ErrSessionNotFound):
		return http.StatusNotFound
	case errors.Is(err, ErrTokenIssuerUnset), errors.Is(err, ErrKeyProviderUnset), errors.Is(err, ErrSessionStoreUnset):
		return http.StatusInternalServerError
	case errors.Is(err, ErrRateLimitExceeded):
		return http.StatusTooManyRequests
	}

	// Category types next
	var (
		cred *CredentialError
		tok  *TokenError
		cfg  *ConfigError
		nf   *NotFoundError
		inr  *InternalError
		rl   *RateLimitError
		val  *ValidationError
		sess *SessionError
	)
	switch {
	case errors.As(err, &val):
		return http.StatusBadRequest
	case errors.As(err, &rl):
		return http.StatusTooManyRequests
	case errors.As(err, &cred):
		return http.StatusUnauthorized
	case errors.As(err, &tok):
		return http.StatusUnauthorized
	case errors.As(err, &sess):
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
	case errors.Is(err, ErrTokenRevoked):
		return "token_revoked"
	case errors.Is(err, ErrTokenTypeMismatch):
		return "token_type_mismatch"
	case errors.Is(err, ErrStrategyNotFound):
		return "strategy_not_found"
	case errors.Is(err, ErrSessionNotFound):
		return "session_not_found"
	case errors.Is(err, ErrTokenIssuerUnset):
		return "config_token_issuer_unset"
	case errors.Is(err, ErrKeyProviderUnset):
		return "config_key_provider_unset"
	case errors.Is(err, ErrSessionStoreUnset):
		return "config_session_store_unset"
	case errors.Is(err, ErrRateLimitExceeded):
		return "rate_limit_exceeded"
	case errors.Is(err, ErrUserNotFound):
		return "user_not_found"
	}

	// Category types next
	var (
		cred *CredentialError
		tok  *TokenError
		cfg  *ConfigError
		nf   *NotFoundError
		inr  *InternalError
		rl   *RateLimitError
		val  *ValidationError
		sess *SessionError
	)
	switch {
	case errors.As(err, &val):
		return "validation_error"
	case errors.As(err, &rl):
		return "rate_limit_error"
	case errors.As(err, &cred):
		return "invalid_credentials"
	case errors.As(err, &tok):
		return "token_error"
	case errors.As(err, &sess):
		return "session_error"
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

// ErrorResponse represents a structured HTTP error response
type ErrorResponse struct {
	Status     int               `json:"status"`
	Code       string            `json:"code"`
	Message    string            `json:"message"`
	Fields     map[string]string `json:"fields,omitempty"`     // For validation errors
	RetryAfter int               `json:"retry_after,omitempty"` // For rate limit errors (seconds)
}

// ErrorResponseForError creates a structured error response from an error
func ErrorResponseForError(err error) ErrorResponse {
	resp := ErrorResponse{
		Status:  HTTPStatusForError(err),
		Code:    ErrorCodeForError(err),
		Message: err.Error(),
	}

	// Add extra fields for specific error types
	var val *ValidationError
	if errors.As(err, &val) && val.Fields != nil {
		resp.Fields = val.Fields
	}

	var rl *RateLimitError
	if errors.As(err, &rl) && rl.RetryAfter > 0 {
		resp.RetryAfter = int(rl.RetryAfter / time.Second)
	}

	return resp
}

// RetryAfterForError returns the Retry-After header value for rate limit errors
// Returns 0 if the error is not a rate limit error
func RetryAfterForError(err error) time.Duration {
	var rl *RateLimitError
	if errors.As(err, &rl) {
		return rl.RetryAfter
	}
	return 0
}
