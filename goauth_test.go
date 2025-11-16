package goauth

import (
	"context"
	"fmt"
	"testing"
)

func TestMain(m *testing.M) {
	// Setup can go here
	fmt.Println("Starting goauth tests...")
	m.Run()
}

func TestNew(t *testing.T) {
	t.Run("should return a new instance of GoAuth", func(t *testing.T) {
		goauth := New()

		if goauth == nil {
			t.Errorf("goauth should not be nil")
		}
	})
}

func TestRegisterStrategy(t *testing.T) {
	t.Run("should register a new strategy", func(t *testing.T) {
		goauth := New()
		goauth.RegisterStrategy(&LocalStrategy{})
		goauth.RegisterStrategy(&JWTStrategy{})

		if _, ok := goauth.strategies["local"]; !ok {
			t.Errorf("goauth.Strategies should contain a local strategy")
		}

		if _, ok := goauth.strategies["jwt"]; !ok {
			t.Errorf("goauth.Strategies should contain a jwt strategy")
		}
	})
}

func TestAuthenticate(t *testing.T) {
	goauth := New()

	t.Run("should authenticate a user with local strategy", func(t *testing.T) {
		goauth.RegisterStrategy(&LocalStrategy{
			LookupUserWith: func(ctx context.Context, params AuthParams) (Authenticatable, error) {
				return &User{
					ID:       "test",
					Username: "test",
					Email:    "test@test.com",
				}, nil
			},
		})

		result, err := goauth.Authenticate(context.TODO(), "local", AuthParams{
			UsernameOrEmail: "test",
			Password:        "test",
		})

		if err != nil {
			t.Errorf("err should be nil")
		}

		if result == nil {
			t.Errorf("result should not be nil")
			return
		}

		if result.Strategy != "local" {
			t.Errorf("result.Strategy should be local")
			return
		}

		if result.Authenticatable == nil {
			t.Errorf("result.Authenticatable should not be nil")
			return
		}

		if result.Authenticatable.GetID() != "test" {
			t.Errorf("result.Identifier() should be test")
			return
		}

		if result.Authenticatable.GetUsername() != "test" {
			t.Errorf("result.GetUsername() should be test")
			return
		}

		if result.Authenticatable.GetEmail() != "test@test.com" {
			t.Errorf("result.GetEmail() should be test@test.com")
			return
		}
	})

	t.Run("should authenticate a user with jwt strategy", func(t *testing.T) {
		tokenIssuer := NewDefaultTokenIssuer("testsecret")
		tokenIssuer.SetExtraClaimsWith(func(ctx context.Context, authenticatable Authenticatable) map[string]any {
			return map[string]any{
				"role": "admin",
			}
		})
		tokenIssuer.SetIssuer("api.example.com")
		tokenIssuer.SetAudience([]string{"api.example.com", "auth.example.com"})
		tokenIssuer.StoreRefreshTokenWith(func(ctx context.Context, authenticatable Authenticatable, token *Token, refreshing bool) error {
			// use refreshing to determine if the token is being refreshed or not
			return nil
		})

		goauth.RegisterStrategy(&JWTStrategy{
			TokenIssuer: tokenIssuer,
		})
		goauth.SetTokenIssuer(tokenIssuer)

		user := &User{
			ID:       "test",
			Username: "test",
			Email:    "test@test.com",
			Extra: map[string]any{
				"role": "admin",
			},
		}

		accessToken, _, err := goauth.IssueTokens(t.Context(), user)
		if err != nil {
			t.Errorf("err should be nil %v", err)
			return
		}

		result, err := goauth.Authenticate(context.TODO(), "jwt", AuthParams{
			Token: accessToken.Value,
		})

		if err != nil {
			t.Errorf("err should be nil %v", err)
			return
		}

		if result == nil {
			t.Errorf("result should not be nil")
			return
		}

		if result.Strategy != "jwt" {
			t.Errorf("result.Strategy should be jwt")
			return
		}

		if result.Authenticatable == nil {
			t.Errorf("result.Authenticatable should not be nil")
			return
		}

		if result.Authenticatable.GetID() != "test" {
			t.Errorf("result.Identifier() should be test")
			return
		}

		if result.Authenticatable.GetUsername() != "test" {
			t.Errorf("result.GetUsername() should be test")
			return
		}

		if result.Authenticatable.GetEmail() != "test@test.com" {
			t.Errorf("result.GetEmail() should be test@test.com")
			return
		}
	})
}

func TestIssueTokens(t *testing.T) {
	t.Run("should issue access and refresh tokens", func(t *testing.T) {
		var storedRefreshToken string
		tokenIssuer := NewDefaultTokenIssuer("testsecret")
		tokenIssuer.StoreRefreshTokenWith(func(ctx context.Context, authenticatable Authenticatable, token *Token, refreshing bool) error {
			// use refreshing to determine if the token is being refreshed or not
			storedRefreshToken = token.Value
			return nil
		})
		tokenIssuer.SetExtraClaimsWith(func(ctx context.Context, authenticatable Authenticatable) map[string]any {
			return map[string]any{
				"role": "admin",
			}
		})
		tokenIssuer.SetIssuer("api.example.com")
		tokenIssuer.SetAudience([]string{"api.example.com", "auth.example.com"})

		goauth := New()
		goauth.SetTokenIssuer(tokenIssuer)

		goauth.RegisterStrategy(&LocalStrategy{
			LookupUserWith: func(ctx context.Context, params AuthParams) (Authenticatable, error) {
				return &User{
					ID:       "test",
					Username: "test",
					Email:    "test@test.com",
				}, nil
			},
		})

		result, accessToken, refreshToken, err := goauth.AuthenticateAndIssueTokens(context.TODO(), "local", AuthParams{
			UsernameOrEmail: "test",
			Password:        "test",
		})

		if err != nil {
			t.Errorf("err should be nil")
		}

		if result == nil {
			t.Errorf("result should not be nil")
			return
		}

		if result.Strategy != "local" {
			t.Errorf("result.Strategy should be local")
			return
		}

		if result.Authenticatable == nil {
			t.Errorf("result.Authenticatable should not be nil")
			return
		}

		if result.Authenticatable.GetID() != "test" {
			t.Errorf("result.Identifier() should be test")
			return
		}

		if result.Authenticatable.GetUsername() != "test" {
			t.Errorf("result.GetUsername() should be test")
			return
		}

		if result.Authenticatable.GetEmail() != "test@test.com" {
			t.Errorf("result.GetEmail() should be test@test.com")
			return
		}

		if accessToken == nil {
			t.Errorf("accessToken should not be nil")
			return
		}

		if accessToken.Value == "" {
			t.Errorf("accessToken.Value should not be empty")
			return
		}

		if refreshToken == nil {
			t.Errorf("refreshToken should not be nil")
			return
		}

		if refreshToken.Value == "" {
			t.Errorf("refreshToken.Value should not be empty")
			return
		}

		if storedRefreshToken == "" {
			t.Errorf("storedRefreshToken should not be empty")
			return
		}
	})
}

func TestSingleton(t *testing.T) {
	t.Run("registers and retrieves singleton instance", func(t *testing.T) {
		ga := New()
		ga.RegisterSingleton()

		got := GetInstance()
		if got == nil {
			t.Fatalf("expected non-nil singleton instance")
		}
		if got != ga {
			t.Fatalf("expected singleton to equal registered instance")
		}
	})

	t.Run("overwrites previous singleton instance", func(t *testing.T) {
		ga1 := New()
		ga1.RegisterSingleton()
		if GetInstance() != ga1 {
			t.Fatalf("expected first singleton to be ga1")
		}

		ga2 := New()
		ga2.RegisterSingleton()
		if GetInstance() != ga2 {
			t.Fatalf("expected singleton to be overwritten by ga2")
		}
	})

	t.Run("RegisterSingletonOnce sets once and errors on second", func(t *testing.T) {
		// ensure clean state using test replacer
		restore := ReplaceSingletonForTest(nil)
		defer restore()

		ga := New()
		if err := ga.RegisterSingletonOnce(); err != nil {
			t.Fatalf("unexpected error on first RegisterSingletonOnce: %v", err)
		}
		if GetInstance() != ga {
			t.Fatalf("expected singleton to be ga after RegisterSingletonOnce")
		}

		other := New()
		if err := other.RegisterSingletonOnce(); err == nil {
			t.Fatalf("expected error on second RegisterSingletonOnce with different instance")
		}
		if GetInstance() != ga {
			t.Fatalf("expected singleton to remain ga after failed second RegisterSingletonOnce")
		}
	})

	t.Run("ReplaceSingletonForTest replaces and restores", func(t *testing.T) {
		base := New()
		base.RegisterSingleton()
		if GetInstance() != base {
			t.Fatalf("expected base instance registered")
		}

		temp := New()
		restore := ReplaceSingletonForTest(temp)
		if GetInstance() != temp {
			t.Fatalf("expected temp instance during test replacement")
		}
		restore()
		if GetInstance() != base {
			t.Fatalf("expected base instance restored after test replacement")
		}
	})
}
