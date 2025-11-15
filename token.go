package goauth

import (
	"context"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type StoreRefreshTokenFunc func(ctx context.Context, authenticatable Authenticatable, token *Token) error
type SetExtraClaimsFunc func(ctx context.Context, authenticatable Authenticatable) map[string]any
type SetRegisteredClaimsFunc func(ctx context.Context, authenticatable Authenticatable) jwt.RegisteredClaims
type ConvertTokenClaimsFunc func(ctx context.Context, claims *TokenClaims) (Authenticatable, error)

type TokenClaims struct {
	jwt.RegisteredClaims
	ExtraClaims map[string]any `json:"ext,omitempty"`
}

type DefaultTokenIssuer struct {
	secret                  string
	issuer                  string
	audience                []string
	accessTokenExpiresIn    time.Duration
	refreshTokenExpiresIn   time.Duration
	storeRefreshTokenWith   StoreRefreshTokenFunc
	setExtraClaimsWith      SetExtraClaimsFunc
	setRegisteredClaimsWith SetRegisteredClaimsFunc
	convertTokenClaimsWith  ConvertTokenClaimsFunc
}

func NewDefaultTokenIssuer(secret string) *DefaultTokenIssuer {
	ti := &DefaultTokenIssuer{
		secret:                secret,
		issuer:                "goauth",
		audience:              []string{"goauth"},
		accessTokenExpiresIn:  300 * time.Second,  // default 5 minutes
		refreshTokenExpiresIn: 3600 * time.Second, // default 1 hour
	}

	return ti
}

func (ti *DefaultTokenIssuer) SetSecret(secret string) {
	ti.secret = secret
}

func (ti *DefaultTokenIssuer) SetIssuer(issuer string) {
	ti.issuer = issuer
}

func (ti *DefaultTokenIssuer) SetAudience(audience []string) {
	ti.audience = audience
}

func (ti *DefaultTokenIssuer) SetAccessTokenExpiresIn(expiresIn time.Duration) {
	ti.accessTokenExpiresIn = expiresIn
}

func (ti *DefaultTokenIssuer) SetRefreshTokenExpiresIn(expiresIn time.Duration) {
	ti.refreshTokenExpiresIn = expiresIn
}

func (ti *DefaultTokenIssuer) SetStoreRefreshTokenWith(storeRefreshTokenWith StoreRefreshTokenFunc) {
	ti.storeRefreshTokenWith = storeRefreshTokenWith
}

func (ti *DefaultTokenIssuer) SetExtraClaimsWith(setExtraClaimsWith SetExtraClaimsFunc) {
	ti.setExtraClaimsWith = setExtraClaimsWith
}

func (ti *DefaultTokenIssuer) SetRegisteredClaimsWith(setRegisteredClaimsWith SetRegisteredClaimsFunc) {
	ti.setRegisteredClaimsWith = setRegisteredClaimsWith
}

func (ti *DefaultTokenIssuer) SetConvertTokenClaimsWith(convertTokenClaimsWith ConvertTokenClaimsFunc) {
	ti.convertTokenClaimsWith = convertTokenClaimsWith
}

func (ti *DefaultTokenIssuer) CreateAccessToken(ctx context.Context, authenticatable Authenticatable) (*Token, error) {
	extraClaims := make(map[string]any)
	if ti.setExtraClaimsWith != nil {
		extraClaims = ti.setExtraClaimsWith(ctx, authenticatable)
	}

	var registeredClaims jwt.RegisteredClaims
	if ti.setRegisteredClaimsWith != nil {
		registeredClaims = ti.setRegisteredClaimsWith(ctx, authenticatable)
	} else {
		registeredClaims = jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(ti.accessTokenExpiresIn)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Subject:   authenticatable.GetID(),
			Issuer:    ti.issuer,
			Audience:  ti.audience,
		}
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, TokenClaims{
		ExtraClaims:      extraClaims,
		RegisteredClaims: registeredClaims,
	})

	tokenString, err := token.SignedString([]byte(ti.secret))
	if err != nil {
		return nil, err
	}

	return &Token{
		Value:     tokenString,
		ExpiresIn: ti.accessTokenExpiresIn,
	}, nil
}

func (ti *DefaultTokenIssuer) CreateRefreshToken(ctx context.Context, authenticatable Authenticatable) (*Token, error) {
	if ti.storeRefreshTokenWith == nil {
		return nil, fmt.Errorf("store refresh token with function is not set, use SetStoreRefreshTokenWith to set it")
	}

	tokenString := uuid.New().String()
	token := &Token{
		Value:     tokenString,
		ExpiresIn: ti.refreshTokenExpiresIn,
	}

	err := ti.storeRefreshTokenWith(ctx, authenticatable, token)
	if err != nil {
		return nil, err
	}

	return token, nil
}

func (ti *DefaultTokenIssuer) DecodeAccessToken(ctx context.Context, token string) (*TokenClaims, error) {
	jwt, err := jwt.ParseWithClaims(token, &TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(ti.secret), nil
	})

	if err != nil {
		return nil, err
	}

	claims, ok := jwt.Claims.(*TokenClaims)
	if !ok {
		return nil, fmt.Errorf("invalid claims")
	}

	return claims, nil
}

func (ti *DefaultTokenIssuer) ConvertTokenClaims(ctx context.Context, claims *TokenClaims) (Authenticatable, error) {
	if ti.convertTokenClaimsWith != nil {
		return ti.convertTokenClaimsWith(ctx, claims)
	}

	return &User{
		ID: claims.Subject,
	}, nil
}
