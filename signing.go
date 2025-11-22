package goauth

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"errors"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

// SigningMethod represents supported JWT signing algorithms
type SigningMethod string

const (
	// HMAC signing methods (symmetric)
	HS256 SigningMethod = "HS256"
	HS384 SigningMethod = "HS384"
	HS512 SigningMethod = "HS512"

	// RSA signing methods (asymmetric)
	RS256 SigningMethod = "RS256"
	RS384 SigningMethod = "RS384"
	RS512 SigningMethod = "RS512"

	// ECDSA signing methods (asymmetric)
	ES256 SigningMethod = "ES256"
	ES384 SigningMethod = "ES384"
	ES512 SigningMethod = "ES512"
)

// KeyProvider abstracts the signing key management for JWT tokens
type KeyProvider interface {
	// Method returns the JWT signing method
	Method() jwt.SigningMethod
	// SignKey returns the key used for signing tokens
	SignKey() any
	// VerifyKey returns the key used for verifying tokens
	VerifyKey() any
	// Algorithm returns the signing method name
	Algorithm() SigningMethod
}

// HMACKeyProvider implements KeyProvider for HMAC-based signing (HS256, HS384, HS512)
type HMACKeyProvider struct {
	secret []byte
	method SigningMethod
}

// NewHMACKeyProvider creates a new HMAC key provider
func NewHMACKeyProvider(secret []byte, method SigningMethod) (*HMACKeyProvider, error) {
	if len(secret) == 0 {
		return nil, errors.New("secret cannot be empty")
	}

	switch method {
	case HS256, HS384, HS512:
		// valid
	default:
		return nil, fmt.Errorf("invalid HMAC signing method: %s", method)
	}

	return &HMACKeyProvider{
		secret: secret,
		method: method,
	}, nil
}

func (p *HMACKeyProvider) Method() jwt.SigningMethod {
	switch p.method {
	case HS384:
		return jwt.SigningMethodHS384
	case HS512:
		return jwt.SigningMethodHS512
	default:
		return jwt.SigningMethodHS256
	}
}

func (p *HMACKeyProvider) SignKey() any {
	return p.secret
}

func (p *HMACKeyProvider) VerifyKey() any {
	return p.secret
}

func (p *HMACKeyProvider) Algorithm() SigningMethod {
	return p.method
}

// RSAKeyProvider implements KeyProvider for RSA-based signing (RS256, RS384, RS512)
type RSAKeyProvider struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	method     SigningMethod
}

// NewRSAKeyProvider creates a new RSA key provider
// privateKey is required for signing, publicKey is required for verification
// If only verification is needed, privateKey can be nil
func NewRSAKeyProvider(privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey, method SigningMethod) (*RSAKeyProvider, error) {
	if privateKey == nil && publicKey == nil {
		return nil, errors.New("at least one key (private or public) must be provided")
	}

	switch method {
	case RS256, RS384, RS512:
		// valid
	default:
		return nil, fmt.Errorf("invalid RSA signing method: %s", method)
	}

	// If private key is provided but public key is not, derive public from private
	if privateKey != nil && publicKey == nil {
		publicKey = &privateKey.PublicKey
	}

	return &RSAKeyProvider{
		privateKey: privateKey,
		publicKey:  publicKey,
		method:     method,
	}, nil
}

func (p *RSAKeyProvider) Method() jwt.SigningMethod {
	switch p.method {
	case RS384:
		return jwt.SigningMethodRS384
	case RS512:
		return jwt.SigningMethodRS512
	default:
		return jwt.SigningMethodRS256
	}
}

func (p *RSAKeyProvider) SignKey() any {
	return p.privateKey
}

func (p *RSAKeyProvider) VerifyKey() any {
	return p.publicKey
}

func (p *RSAKeyProvider) Algorithm() SigningMethod {
	return p.method
}

// ECDSAKeyProvider implements KeyProvider for ECDSA-based signing (ES256, ES384, ES512)
type ECDSAKeyProvider struct {
	privateKey *ecdsa.PrivateKey
	publicKey  *ecdsa.PublicKey
	method     SigningMethod
}

// NewECDSAKeyProvider creates a new ECDSA key provider
// privateKey is required for signing, publicKey is required for verification
// If only verification is needed, privateKey can be nil
func NewECDSAKeyProvider(privateKey *ecdsa.PrivateKey, publicKey *ecdsa.PublicKey, method SigningMethod) (*ECDSAKeyProvider, error) {
	if privateKey == nil && publicKey == nil {
		return nil, errors.New("at least one key (private or public) must be provided")
	}

	switch method {
	case ES256, ES384, ES512:
		// valid
	default:
		return nil, fmt.Errorf("invalid ECDSA signing method: %s", method)
	}

	// If private key is provided but public key is not, derive public from private
	if privateKey != nil && publicKey == nil {
		publicKey = &privateKey.PublicKey
	}

	return &ECDSAKeyProvider{
		privateKey: privateKey,
		publicKey:  publicKey,
		method:     method,
	}, nil
}

func (p *ECDSAKeyProvider) Method() jwt.SigningMethod {
	switch p.method {
	case ES384:
		return jwt.SigningMethodES384
	case ES512:
		return jwt.SigningMethodES512
	default:
		return jwt.SigningMethodES256
	}
}

func (p *ECDSAKeyProvider) SignKey() any {
	return p.privateKey
}

func (p *ECDSAKeyProvider) VerifyKey() any {
	return p.publicKey
}

func (p *ECDSAKeyProvider) Algorithm() SigningMethod {
	return p.method
}
