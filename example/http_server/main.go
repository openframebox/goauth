package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	goauth "github.com/openframebox/goauth/v2"
)

var (
	ga    *goauth.GoAuth
	store *inMemorySessionStore
)

// inMemorySessionStore - same as main example
type inMemorySessionStore struct {
	mu       sync.RWMutex
	sessions map[string]*sessionData
	tokens   map[string]string
	users    map[string]*goauth.User
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

func (s *inMemorySessionStore) store(ctx context.Context, auth goauth.Authenticatable, session *goauth.SessionInfo, token *goauth.Token, oldToken *string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	userID := auth.GetID()

	if oldToken != nil {
		if oldSessionID, ok := s.tokens[*oldToken]; ok {
			if oldData, exists := s.sessions[oldSessionID]; exists {
				delete(s.tokens, oldData.token)
			}
			delete(s.sessions, oldSessionID)
		}
	}

	s.sessions[session.ID] = &sessionData{
		session: session,
		token:   token.Value,
		userID:  userID,
	}
	s.tokens[token.Value] = session.ID

	if u, ok := auth.(*goauth.User); ok {
		s.users[userID] = u
	} else {
		s.users[userID] = &goauth.User{ID: userID, Username: auth.GetUsername(), Email: auth.GetEmail()}
	}

	return nil
}

func (s *inMemorySessionStore) validate(ctx context.Context, token string) (goauth.Authenticatable, *goauth.SessionInfo, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	sessionID, ok := s.tokens[token]
	if !ok {
		return nil, nil, goauth.ErrTokenRevoked
	}

	data, ok := s.sessions[sessionID]
	if !ok {
		return nil, nil, goauth.ErrSessionNotFound
	}

	if data.session.IsExpired() {
		return nil, nil, goauth.ErrExpiredToken
	}

	user, ok := s.users[data.userID]
	if !ok {
		return nil, nil, goauth.ErrUserNotFound
	}

	return user, data.session, nil
}

func (s *inMemorySessionStore) revoke(ctx context.Context, auth goauth.Authenticatable, sessionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, ok := s.sessions[sessionID]
	if !ok {
		return goauth.ErrSessionNotFound
	}

	if data.userID != auth.GetID() {
		return goauth.ErrInvalidCredentials
	}

	delete(s.tokens, data.token)
	delete(s.sessions, sessionID)
	return nil
}

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

func (s *inMemorySessionStore) getSession(ctx context.Context, token string) (*goauth.SessionInfo, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	sessionID, ok := s.tokens[token]
	if !ok {
		return nil, goauth.ErrTokenRevoked
	}

	data, ok := s.sessions[sessionID]
	if !ok {
		return nil, goauth.ErrSessionNotFound
	}

	return data.session, nil
}

// Request/Response types
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	TokenType    string `json:"token_type"`
	SessionID    string `json:"session_id,omitempty"`
}

type RefreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type SessionResponse struct {
	ID        string         `json:"id"`
	CreatedAt time.Time      `json:"created_at"`
	ExpiresAt time.Time      `json:"expires_at"`
	Metadata  map[string]any `json:"metadata,omitempty"`
}

type UserResponse struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
}

func main() {
	// Initialize store and auth
	store = newInMemorySessionStore()

	keyProvider, err := goauth.NewHMACKeyProvider([]byte("supersecret-change-me"), goauth.HS256)
	if err != nil {
		log.Fatalf("failed to create key provider: %v", err)
	}

	issuer, err := goauth.NewSessionAwareTokenIssuer().
		WithKeyProvider(keyProvider).
		WithIssuer("api.example.local").
		WithAudience([]string{"api.example.local"}).
		WithAccessTokenTTL(15 * time.Minute).
		WithRefreshTokenTTL(7 * 24 * time.Hour).
		WithSessionStore(store.store, store.validate, store.revoke, store.revokeAll).
		WithListSessions(store.list).
		WithGetSession(store.getSession).
		WithSessionMetadataExtractor(extractSessionMetadata).
		Build()

	if err != nil {
		log.Fatalf("failed to build token issuer: %v", err)
	}

	ga = goauth.New()
	ga.SetTokenIssuer(issuer)

	// Register strategies
	localStrategy := goauth.NewLocalStrategy(lookupUser)
	ga.RegisterStrategy(localStrategy)

	jwtStrategy := goauth.NewJWTStrategy(issuer).WithExpectedType(goauth.AccessToken)
	ga.RegisterStrategy(jwtStrategy)

	// HTTP routes
	http.HandleFunc("/login", handleLogin)
	http.HandleFunc("/refresh", handleRefresh)
	http.HandleFunc("/logout", authMiddleware(handleLogout))
	http.HandleFunc("/logout-all", authMiddleware(handleLogoutAll))
	http.HandleFunc("/me", authMiddleware(handleMe))
	http.HandleFunc("/sessions", authMiddleware(handleSessions))

	log.Println("Server starting on :8080")
	log.Println("Endpoints:")
	log.Println("  POST /login         - Login with username/password")
	log.Println("  POST /refresh       - Refresh access token")
	log.Println("  POST /logout        - Logout current session")
	log.Println("  POST /logout-all    - Logout all sessions")
	log.Println("  GET  /me            - Get current user (protected)")
	log.Println("  GET  /sessions      - List active sessions (protected)")

	log.Fatal(http.ListenAndServe(":8080", nil))
}

func lookupUser(ctx context.Context, params goauth.AuthParams) (goauth.Authenticatable, error) {
	// Demo: accept specific users
	users := map[string]string{
		"alice": "password123",
		"bob":   "secret456",
	}

	password, exists := users[params.UsernameOrEmail]
	if !exists || password != params.Password {
		return nil, goauth.ErrInvalidCredentials
	}

	return &goauth.User{
		ID:       "user-" + params.UsernameOrEmail,
		Username: params.UsernameOrEmail,
		Email:    params.UsernameOrEmail + "@example.com",
	}, nil
}

func extractSessionMetadata(ctx context.Context) map[string]any {
	// In real app, extract from request context
	return map[string]any{
		"created_at": time.Now().Format(time.RFC3339),
	}
}

// Handlers

func handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "POST only")
		return
	}

	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "Invalid JSON")
		return
	}

	result, pair, err := ga.AuthenticateAndIssueTokenPair(r.Context(), "local", goauth.AuthParams{
		UsernameOrEmail: req.Username,
		Password:        req.Password,
	})
	if err != nil {
		resp := goauth.ErrorResponseForError(err)
		writeError(w, resp.Status, resp.Code, resp.Message)
		return
	}

	writeJSON(w, http.StatusOK, TokenResponse{
		AccessToken:  pair.Access.Value,
		RefreshToken: pair.Refresh.Value,
		ExpiresIn:    int(pair.Access.ExpiresIn.Seconds()),
		TokenType:    "Bearer",
		SessionID:    pair.Access.SessionID,
	})

	log.Printf("User %s logged in, session: %s", result.Authenticatable.GetUsername(), pair.Access.SessionID)
}

func handleRefresh(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "POST only")
		return
	}

	var req RefreshRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "Invalid JSON")
		return
	}

	pair, err := ga.RefreshTokenPair(r.Context(), req.RefreshToken)
	if err != nil {
		resp := goauth.ErrorResponseForError(err)
		writeError(w, resp.Status, resp.Code, resp.Message)
		return
	}

	writeJSON(w, http.StatusOK, TokenResponse{
		AccessToken:  pair.Access.Value,
		RefreshToken: pair.Refresh.Value,
		ExpiresIn:    int(pair.Access.ExpiresIn.Seconds()),
		TokenType:    "Bearer",
		SessionID:    pair.Access.SessionID,
	})
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "POST only")
		return
	}

	var req RefreshRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "Invalid JSON")
		return
	}

	if err := ga.RevokeToken(r.Context(), req.RefreshToken); err != nil {
		resp := goauth.ErrorResponseForError(err)
		writeError(w, resp.Status, resp.Code, resp.Message)
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "logged_out"})
}

func handleLogoutAll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "POST only")
		return
	}

	user := r.Context().Value("user").(goauth.Authenticatable)

	if err := ga.RevokeAllTokens(r.Context(), user); err != nil {
		resp := goauth.ErrorResponseForError(err)
		writeError(w, resp.Status, resp.Code, resp.Message)
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "all_sessions_revoked"})
}

func handleMe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "GET only")
		return
	}

	user := r.Context().Value("user").(goauth.Authenticatable)

	writeJSON(w, http.StatusOK, UserResponse{
		ID:       user.GetID(),
		Username: user.GetUsername(),
		Email:    user.GetEmail(),
	})
}

func handleSessions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "GET only")
		return
	}

	user := r.Context().Value("user").(goauth.Authenticatable)

	sessions, err := ga.ListSessions(r.Context(), user)
	if err != nil {
		resp := goauth.ErrorResponseForError(err)
		writeError(w, resp.Status, resp.Code, resp.Message)
		return
	}

	var response []SessionResponse
	for _, s := range sessions {
		response = append(response, SessionResponse{
			ID:        s.ID,
			CreatedAt: s.CreatedAt,
			ExpiresAt: s.ExpiresAt,
			Metadata:  s.Metadata,
		})
	}

	writeJSON(w, http.StatusOK, response)
}

// Middleware

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			writeError(w, http.StatusUnauthorized, "token_missing", "Authorization header required")
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			writeError(w, http.StatusUnauthorized, "token_invalid", "Bearer token required")
			return
		}

		token := parts[1]
		result, err := ga.Authenticate(r.Context(), "jwt", goauth.AuthParams{Token: token})
		if err != nil {
			resp := goauth.ErrorResponseForError(err)
			writeError(w, resp.Status, resp.Code, resp.Message)
			return
		}

		ctx := context.WithValue(r.Context(), "user", result.Authenticatable)
		next(w, r.WithContext(ctx))
	}
}

// Helpers

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]any{
		"error":   code,
		"message": message,
	})
}
