package goauth

import (
	"context"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type TokenClaims struct {
	jwt.RegisteredClaims
	Username    string         `json:"username,omitempty"`
	Email       string         `json:"email,omitempty"`
	ExtraClaims map[string]any `json:"ext,omitempty"`
}

type DefaultTokenIssuer struct {
	secret                       string
	issuer                       string
	audience                     []string
	accessTokenExpiresIn         time.Duration
	refreshTokenExpiresIn        time.Duration
	storeRefreshTokenWith        StoreRefreshTokenFunc
	setExtraClaimsWith           SetExtraClaimsFunc
	setRegisteredClaimsWith      SetRegisteredClaimsFunc
	convertAccessTokenClaimsWith ConvertAccessTokenClaimsFunc
	validateRefreshTokenWith     ValidateRefreshTokenFunc
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

func (ti *DefaultTokenIssuer) StoreRefreshTokenWith(storeRefreshTokenWith StoreRefreshTokenFunc) {
	ti.storeRefreshTokenWith = storeRefreshTokenWith
}

func (ti *DefaultTokenIssuer) SetExtraClaimsWith(setExtraClaimsWith SetExtraClaimsFunc) {
	ti.setExtraClaimsWith = setExtraClaimsWith
}

func (ti *DefaultTokenIssuer) SetRegisteredClaimsWith(setRegisteredClaimsWith SetRegisteredClaimsFunc) {
	ti.setRegisteredClaimsWith = setRegisteredClaimsWith
}

func (ti *DefaultTokenIssuer) ConvertAccessTokenClaimsWith(convertAccessTokenClaimsWith ConvertAccessTokenClaimsFunc) {
	ti.convertAccessTokenClaimsWith = convertAccessTokenClaimsWith
}

func (ti *DefaultTokenIssuer) ValidateRefreshTokenWith(validateRefreshTokenWith ValidateRefreshTokenFunc) {
	ti.validateRefreshTokenWith = validateRefreshTokenWith
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
		RegisteredClaims: registeredClaims,
		Username:         authenticatable.GetUsername(),
		Email:            authenticatable.GetEmail(),
		ExtraClaims:      extraClaims,
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

func (ti *DefaultTokenIssuer) CreateRefreshToken(ctx context.Context, authenticatable Authenticatable, refreshing bool) (*Token, error) {
	if ti.storeRefreshTokenWith == nil {
		return nil, fmt.Errorf("store refresh token with function is not set, use SetStoreRefreshTokenWith to set it")
	}

	tokenString := uuid.New().String()
	token := &Token{
		Value:     tokenString,
		ExpiresIn: ti.refreshTokenExpiresIn,
	}

	err := ti.storeRefreshTokenWith(ctx, authenticatable, token, refreshing)
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

func (ti *DefaultTokenIssuer) ConvertAccessTokenClaims(ctx context.Context, claims *TokenClaims) (Authenticatable, error) {
	if ti.convertAccessTokenClaimsWith != nil {
		return ti.convertAccessTokenClaimsWith(ctx, claims)
	}

	return &User{
		ID:        claims.Subject,
		Username:  claims.Username,
		Email:     claims.Email,
		ExtraData: claims.ExtraClaims,
	}, nil
}

func (ti *DefaultTokenIssuer) ValidateRefreshToken(ctx context.Context, token string) (Authenticatable, error) {
	if ti.validateRefreshTokenWith == nil {
		return nil, fmt.Errorf("validate refresh token with function is not set, use SetValidateRefreshTokenWith to set it")
	}

	authenticatable, err := ti.validateRefreshTokenWith(ctx, token)
	if err != nil {
		return nil, err
	}

	return authenticatable, nil
}
