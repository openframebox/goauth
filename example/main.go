package main

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	goauth "github.com/openframebox/goauth"
)

// inMemoryRefreshStore is a simple in-memory store for refresh tokens.
// It supports basic rotation by removing the previous token for a user when refreshing.
type inMemoryRefreshStore struct {
	mu            sync.Mutex
	tokenToUserID map[string]string
	userIDToToken map[string]string
	usersByID     map[string]*goauth.User
}

func newInMemoryRefreshStore() *inMemoryRefreshStore {
	return &inMemoryRefreshStore{
		tokenToUserID: make(map[string]string),
		userIDToToken: make(map[string]string),
		usersByID:     make(map[string]*goauth.User),
	}
}

func (s *inMemoryRefreshStore) store(ctx context.Context, authenticatable goauth.Authenticatable, token *goauth.Token, refreshing bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	userID := authenticatable.GetID()

	// On rotation, delete old token mapping for this user if exists
	if refreshing {
		if oldTok, ok := s.userIDToToken[userID]; ok {
			delete(s.tokenToUserID, oldTok)
		}
	}

	s.tokenToUserID[token.Value] = userID
	s.userIDToToken[userID] = token.Value

	// Keep a reference user for demo lookup (username/email optional)
	if u, ok := authenticatable.(*goauth.User); ok {
		s.usersByID[userID] = u
	} else {
		s.usersByID[userID] = &goauth.User{ID: userID}
	}
	return nil
}

func (s *inMemoryRefreshStore) validate(ctx context.Context, token string) (goauth.Authenticatable, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	userID, ok := s.tokenToUserID[token]
	if !ok {
		return nil, fmt.Errorf("refresh token not found or revoked")
	}
	if u, ok := s.usersByID[userID]; ok {
		return u, nil
	}
	return &goauth.User{ID: userID}, nil
}

func main() {
	ctx := context.Background()

	// Configure token issuer
	issuer := goauth.NewDefaultTokenIssuer("supersecret-change-me")
	issuer.SetIssuer("api.example.local")
	issuer.SetAudience([]string{"api.example.local"})
	issuer.SetAccessTokenExpiresIn(2 * time.Minute)
	issuer.SetRefreshTokenExpiresIn(15 * time.Minute)

	// In-memory refresh token storage (for demo)
	store := newInMemoryRefreshStore()
	issuer.StoreRefreshTokenWith(store.store)
	issuer.ValidateRefreshTokenWith(store.validate)

	// Add extra claims into access token and be able to reconstruct the user from claims
	issuer.SetExtraClaimsWith(func(ctx context.Context, a goauth.Authenticatable) map[string]any {
		return map[string]any{
			"username": a.GetUsername(),
			"email":    a.GetEmail(),
			"role":     "admin", // demo custom claim
		}
	})
	// Rely on default ConvertAccessTokenClaims which maps subject/username/email and passes through extra claims.

	// Orchestrator
	ga := goauth.New()
	ga.SetTokenIssuer(issuer)

	// Local strategy using a trivial credential check for demo purposes
	ga.RegisterStrategy(&goauth.LocalStrategy{LookupUserWith: func(params goauth.AuthParams) (goauth.Authenticatable, error) {
		// Demo: accept any non-empty username/password, construct an example user
		if params.UsernameOrEmail == "" || params.Password == "" {
			return nil, fmt.Errorf("missing credentials")
		}
		u := &goauth.User{
			ID:       "user-" + params.UsernameOrEmail,
			Username: params.UsernameOrEmail,
			Email:    params.UsernameOrEmail + "@example.local",
		}
		return u, nil
	}})

	// JWT strategy for authenticating incoming requests by bearer token
	ga.RegisterStrategy(&goauth.JWTStrategy{TokenIssuer: issuer})

	fmt.Println("== Demo: Local login -> issue tokens ==")
	authRes, accessTok, refreshTok, err := ga.AuthenticateAndIssueTokens(ctx, "local", goauth.AuthParams{
		UsernameOrEmail: "alice",
		Password:        "s3cret",
		Extra:           map[string]any{"source": "example"}, // optional metadata
	})
	if err != nil {
		log.Fatalf("login failed: %v", err)
	}
	fmt.Printf("Authenticated as: id=%s user=%s email=%s via=%s\n",
		authRes.Authenticatable.GetID(), authRes.Authenticatable.GetUsername(), authRes.Authenticatable.GetEmail(), authRes.Strategy)
	fmt.Printf("Access Token (exp %s): %s\n", issuerExpiry(accessTok.ExpiresIn), accessTok.Value)
	fmt.Printf("Refresh Token (exp %s): %s\n\n", issuerExpiry(refreshTok.ExpiresIn), refreshTok.Value)

	fmt.Println("== Demo: Authenticate request using JWT strategy ==")
	jwtRes, err := ga.Authenticate(ctx, "jwt", goauth.AuthParams{Token: accessTok.Value})
	if err != nil {
		log.Fatalf("jwt auth failed: %v", err)
	}
	fmt.Printf("JWT resolved user: id=%s user=%s email=%s via=%s\n\n",
		jwtRes.Authenticatable.GetID(), jwtRes.Authenticatable.GetUsername(), jwtRes.Authenticatable.GetEmail(), jwtRes.Strategy)

	fmt.Println("== Demo: Refresh tokens (rotation) ==")
	newAccess, newRefresh, err := ga.RefreshToken(ctx, refreshTok.Value)
	if err != nil {
		log.Fatalf("refresh failed: %v", err)
	}
	fmt.Printf("New Access Token (exp %s): %s\n", issuerExpiry(newAccess.ExpiresIn), newAccess.Value)
	fmt.Printf("New Refresh Token (exp %s): %s\n\n", issuerExpiry(newRefresh.ExpiresIn), newRefresh.Value)

	fmt.Println("Done.")
}

func issuerExpiry(d time.Duration) string {
	return time.Now().Add(d).Format(time.RFC3339)
}
