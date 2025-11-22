package main

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	goauth "github.com/openframebox/goauth/v2"
)

// inMemorySessionStore is a session-aware in-memory store for refresh tokens
// It supports multiple sessions per user for multi-device login
type inMemorySessionStore struct {
	mu       sync.RWMutex
	sessions map[string]*sessionData // sessionID -> session data
	tokens   map[string]string       // token -> sessionID
	users    map[string]*goauth.User // userID -> user data
}

type sessionData struct {
	session *goauth.SessionInfo
	token   string
	userID  string
}

func newInMemorySessionStore() *inMemorySessionStore {
	return &inMemorySessionStore{
		sessions: make(map[string]*sessionData),
		tokens:   make(map[string]string),
		users:    make(map[string]*goauth.User),
	}
}

// StoreSession stores a new session with its refresh token
func (s *inMemorySessionStore) store(ctx context.Context, auth goauth.Authenticatable, session *goauth.SessionInfo, token *goauth.Token, oldToken *string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	userID := auth.GetID()

	// If rotating, invalidate the old token
	if oldToken != nil {
		if oldSessionID, ok := s.tokens[*oldToken]; ok {
			// Get the old session data before deleting
			if oldData, exists := s.sessions[oldSessionID]; exists {
				// Delete old token mapping
				delete(s.tokens, oldData.token)
			}
			// Remove old session if it's being replaced
			delete(s.sessions, oldSessionID)
		}
	}

	// Store new session
	s.sessions[session.ID] = &sessionData{
		session: session,
		token:   token.Value,
		userID:  userID,
	}
	s.tokens[token.Value] = session.ID

	// Store user for lookup
	if u, ok := auth.(*goauth.User); ok {
		s.users[userID] = u
	} else {
		s.users[userID] = &goauth.User{ID: userID, Username: auth.GetUsername(), Email: auth.GetEmail()}
	}

	return nil
}

// ValidateSession validates a refresh token and returns the user and session
func (s *inMemorySessionStore) validate(ctx context.Context, token string) (goauth.Authenticatable, *goauth.SessionInfo, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	sessionID, ok := s.tokens[token]
	if !ok {
		return nil, nil, fmt.Errorf("refresh token not found or revoked")
	}

	data, ok := s.sessions[sessionID]
	if !ok {
		return nil, nil, fmt.Errorf("session not found")
	}

	// Check expiry
	if data.session.IsExpired() {
		return nil, nil, fmt.Errorf("session expired")
	}

	user, ok := s.users[data.userID]
	if !ok {
		return nil, nil, fmt.Errorf("user not found")
	}

	return user, data.session, nil
}

// RevokeSession revokes a specific session
func (s *inMemorySessionStore) revoke(ctx context.Context, auth goauth.Authenticatable, sessionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, ok := s.sessions[sessionID]
	if !ok {
		return fmt.Errorf("session not found")
	}

	// Verify user owns this session
	if data.userID != auth.GetID() {
		return fmt.Errorf("session does not belong to user")
	}

	delete(s.tokens, data.token)
	delete(s.sessions, sessionID)
	return nil
}

// RevokeAllSessions revokes all sessions for a user
func (s *inMemorySessionStore) revokeAll(ctx context.Context, auth goauth.Authenticatable) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	userID := auth.GetID()
	for sessionID, data := range s.sessions {
		if data.userID == userID {
			delete(s.tokens, data.token)
			delete(s.sessions, sessionID)
		}
	}
	return nil
}

// ListSessions lists all active sessions for a user
func (s *inMemorySessionStore) list(ctx context.Context, auth goauth.Authenticatable) ([]*goauth.SessionInfo, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	userID := auth.GetID()
	var sessions []*goauth.SessionInfo
	for _, data := range s.sessions {
		if data.userID == userID && !data.session.IsExpired() {
			sessions = append(sessions, data.session)
		}
	}
	return sessions, nil
}

// GetSession returns session info by token
func (s *inMemorySessionStore) getSession(ctx context.Context, token string) (*goauth.SessionInfo, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	sessionID, ok := s.tokens[token]
	if !ok {
		return nil, fmt.Errorf("token not found")
	}

	data, ok := s.sessions[sessionID]
	if !ok {
		return nil, fmt.Errorf("session not found")
	}

	return data.session, nil
}

func main() {
	ctx := context.Background()

	// Create session store
	store := newInMemorySessionStore()

	// Configure session-aware token issuer using builder pattern
	keyProvider, err := goauth.NewHMACKeyProvider([]byte("supersecret-change-me-in-production"), goauth.HS256)
	if err != nil {
		log.Fatalf("failed to create key provider: %v", err)
	}

	issuer, err := goauth.NewSessionAwareTokenIssuer().
		WithKeyProvider(keyProvider).
		WithIssuer("api.example.local").
		WithAudience([]string{"api.example.local"}).
		WithAccessTokenTTL(5 * time.Minute).
		WithRefreshTokenTTL(7 * 24 * time.Hour).
		WithSessionStore(store.store, store.validate, store.revoke, store.revokeAll).
		WithListSessions(store.list).
		WithGetSession(store.getSession).
		WithExtraClaims(func(ctx context.Context, a goauth.Authenticatable) map[string]any {
			return map[string]any{
				"role": "admin", // demo custom claim
			}
		}).
		WithSessionMetadataExtractor(func(ctx context.Context) map[string]any {
			// In real app, extract device info, IP, user agent from context
			return map[string]any{
				"device":     "browser",
				"ip":         "127.0.0.1",
				"user_agent": "Mozilla/5.0",
			}
		}).
		Build()

	if err != nil {
		log.Fatalf("failed to build token issuer: %v", err)
	}

	// Create GoAuth orchestrator
	ga := goauth.New()
	ga.SetTokenIssuer(issuer)

	// Register local strategy with builder pattern
	localStrategy := goauth.NewLocalStrategy(func(ctx context.Context, params goauth.AuthParams) (goauth.Authenticatable, error) {
		// Demo: accept any non-empty username/password
		if params.UsernameOrEmail == "" || params.Password == "" {
			return nil, goauth.ErrInvalidCredentials
		}
		return &goauth.User{
			ID:       "user-" + params.UsernameOrEmail,
			Username: params.UsernameOrEmail,
			Email:    params.UsernameOrEmail + "@example.local",
		}, nil
	})
	ga.RegisterStrategy(localStrategy)

	// Register JWT strategy with builder pattern
	jwtStrategy := goauth.NewJWTStrategy(issuer).
		WithExpectedType(goauth.AccessToken)
	ga.RegisterStrategy(jwtStrategy)

	fmt.Println("=== Demo: Multi-Session Token Issuer ===")
	fmt.Println()

	// --- Login from first device ---
	fmt.Println("== 1. Login from Device 1 (Browser) ==")
	authRes, pair, err := ga.AuthenticateAndIssueTokenPair(ctx, "local", goauth.AuthParams{
		UsernameOrEmail: "alice",
		Password:        "s3cret",
	})
	if err != nil {
		log.Fatalf("login failed: %v", err)
	}

	fmt.Printf("Authenticated: id=%s user=%s\n", authRes.Authenticatable.GetID(), authRes.Authenticatable.GetUsername())
	fmt.Printf("Session ID: %s\n", pair.Access.SessionID)
	fmt.Printf("Access Token (exp %s): %s...\n", formatExpiry(pair.Access.ExpiresIn), truncate(pair.Access.Value, 50))
	fmt.Printf("Refresh Token: %s\n\n", pair.Refresh.Value)

	device1RefreshToken := pair.Refresh.Value

	// --- Login from second device ---
	fmt.Println("== 2. Login from Device 2 (Mobile App) ==")
	_, pair2, err := ga.AuthenticateAndIssueTokenPair(ctx, "local", goauth.AuthParams{
		UsernameOrEmail: "alice",
		Password:        "s3cret",
	})
	if err != nil {
		log.Fatalf("login failed: %v", err)
	}

	fmt.Printf("Session ID: %s\n", pair2.Access.SessionID)
	fmt.Printf("Refresh Token: %s\n\n", pair2.Refresh.Value)

	device2RefreshToken := pair2.Refresh.Value

	// --- List all sessions ---
	fmt.Println("== 3. List Active Sessions ==")
	sessions, err := ga.ListSessions(ctx, authRes.Authenticatable)
	if err != nil {
		log.Fatalf("list sessions failed: %v", err)
	}
	fmt.Printf("Active sessions for user %s: %d\n", authRes.Authenticatable.GetID(), len(sessions))
	for i, sess := range sessions {
		device, _ := sess.GetMetadataString("device")
		fmt.Printf("  %d. Session %s (device: %s, expires: %s)\n",
			i+1, sess.ID, device, sess.ExpiresAt.Format(time.RFC3339))
	}
	fmt.Println()

	// --- Authenticate with JWT ---
	fmt.Println("== 4. Authenticate Request with JWT ==")
	jwtRes, err := ga.Authenticate(ctx, "jwt", goauth.AuthParams{Token: pair.Access.Value})
	if err != nil {
		log.Fatalf("jwt auth failed: %v", err)
	}
	fmt.Printf("JWT resolved: id=%s user=%s\n\n", jwtRes.Authenticatable.GetID(), jwtRes.Authenticatable.GetUsername())

	// --- Refresh token from device 1 ---
	fmt.Println("== 5. Refresh Token (Device 1) ==")
	newPair, err := ga.RefreshTokenPair(ctx, device1RefreshToken)
	if err != nil {
		log.Fatalf("refresh failed: %v", err)
	}
	fmt.Printf("New Session ID: %s (should be same as before)\n", newPair.Access.SessionID)
	fmt.Printf("New Refresh Token: %s\n", newPair.Refresh.Value)
	fmt.Printf("Old token invalidated: %v\n\n", device1RefreshToken != newPair.Refresh.Value)

	// --- Revoke device 2 session ---
	fmt.Println("== 6. Revoke Device 2 Session ==")
	session2, _ := store.getSession(ctx, device2RefreshToken)
	err = ga.RevokeSession(ctx, authRes.Authenticatable, session2.ID)
	if err != nil {
		log.Fatalf("revoke session failed: %v", err)
	}
	fmt.Printf("Revoked session: %s\n", session2.ID)

	// Try to use revoked token
	_, err = ga.RefreshTokenPair(ctx, device2RefreshToken)
	if err != nil {
		fmt.Printf("Device 2 refresh correctly failed: %v\n\n", err)
	}

	// --- Final session count ---
	fmt.Println("== 7. Final Session Count ==")
	sessions, _ = ga.ListSessions(ctx, authRes.Authenticatable)
	fmt.Printf("Remaining active sessions: %d\n\n", len(sessions))

	fmt.Println("=== Demo Complete ===")
}

func formatExpiry(d time.Duration) string {
	return time.Now().Add(d).Format(time.RFC3339)
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen]
}
