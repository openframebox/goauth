package goauth

import "time"

// TokenType represents the type of token (access or refresh)
type TokenType string

const (
	AccessToken  TokenType = "access"
	RefreshToken TokenType = "refresh"
)

// AuthParams contains authentication parameters passed to strategies
type AuthParams struct {
	UsernameOrEmail string
	Password        string
	Token           string
	Extra           map[string]any
}

// GetExtra returns the value for a key from Extra map
func (ap *AuthParams) GetExtra(key string) (any, bool) {
	if ap.Extra == nil {
		return nil, false
	}
	v, ok := ap.Extra[key]
	return v, ok
}

// GetExtraString returns a string value from Extra map
func (ap *AuthParams) GetExtraString(key string) (string, bool) {
	v, ok := ap.GetExtra(key)
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	return s, ok
}

// GetExtraInt returns an int value from Extra map
func (ap *AuthParams) GetExtraInt(key string) (int, bool) {
	v, ok := ap.GetExtra(key)
	if !ok {
		return 0, false
	}
	switch i := v.(type) {
	case int:
		return i, true
	case int64:
		return int(i), true
	case float64:
		return int(i), true
	default:
		return 0, false
	}
}

// GetExtraBool returns a bool value from Extra map
func (ap *AuthParams) GetExtraBool(key string) (bool, bool) {
	v, ok := ap.GetExtra(key)
	if !ok {
		return false, false
	}
	b, ok := v.(bool)
	return b, ok
}

// Validate checks if the AuthParams has valid data for authentication
func (ap *AuthParams) Validate() error {
	// At minimum, either username/email+password or token must be provided
	hasCredentials := ap.UsernameOrEmail != "" && ap.Password != ""
	hasToken := ap.Token != ""

	if !hasCredentials && !hasToken {
		return &ValidationError{
			Msg: "authentication parameters required",
			Fields: map[string]string{
				"credentials": "username/email and password or token required",
			},
		}
	}
	return nil
}

// AuthResult contains the result of a successful authentication
type AuthResult struct {
	Authenticatable Authenticatable
	Strategy        string
	Metadata        map[string]any // NEW: additional context from authentication
}

// Token represents an authentication token (access or refresh)
type Token struct {
	Value     string
	Type      TokenType
	ExpiresIn time.Duration
	IssuedAt  time.Time
	SessionID string // For multi-session support
}

// TokenPair contains both access and refresh tokens
type TokenPair struct {
	Access  *Token
	Refresh *Token
}

// SessionInfo contains session metadata for multi-session support
type SessionInfo struct {
	ID        string
	UserID    string
	CreatedAt time.Time
	ExpiresAt time.Time
	Metadata  map[string]any // device, IP, user agent, location, etc.
}

// GetMetadata returns a value from session metadata
func (s *SessionInfo) GetMetadata(key string) (any, bool) {
	if s.Metadata == nil {
		return nil, false
	}
	v, ok := s.Metadata[key]
	return v, ok
}

// GetMetadataString returns a string value from session metadata
func (s *SessionInfo) GetMetadataString(key string) (string, bool) {
	v, ok := s.GetMetadata(key)
	if !ok {
		return "", false
	}
	str, ok := v.(string)
	return str, ok
}

// IsExpired checks if the session has expired
func (s *SessionInfo) IsExpired() bool {
	return time.Now().After(s.ExpiresAt)
}

// User is a default implementation of Authenticatable
type User struct {
	ID       string
	Username string
	Email    string
	Extra    map[string]any
}

func (u *User) GetID() string {
	return u.ID
}

func (u *User) GetUsername() string {
	return u.Username
}

func (u *User) GetEmail() string {
	return u.Email
}

func (u *User) GetExtra() map[string]any {
	return u.Extra
}
