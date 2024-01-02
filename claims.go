package guth

import "github.com/golang-jwt/jwt/v5"

type RegisteredClaims struct {
	Issuer    string           `json:"iss,omitempty"`
	Subject   string           `json:"sub,omitempty"`
	Audience  jwt.ClaimStrings `json:"aud,omitempty"`
	ExpiresAt *jwt.NumericDate `json:"exp,omitempty"`
	NotBefore *jwt.NumericDate `json:"nbf,omitempty"`
	IssuedAt  *jwt.NumericDate `json:"iat,omitempty"`
	ID        string           `json:"jti,omitempty"`
	AuthID    *uint64          `json:"aid,omitempty"`
}

// GetExpirationTime implements the Claims interface.
func (c RegisteredClaims) GetExpirationTime() (*jwt.NumericDate, error) {
	return c.ExpiresAt, nil
}

// GetNotBefore implements the Claims interface.
func (c RegisteredClaims) GetNotBefore() (*jwt.NumericDate, error) {
	return c.NotBefore, nil
}

// GetIssuedAt implements the Claims interface.
func (c RegisteredClaims) GetIssuedAt() (*jwt.NumericDate, error) {
	return c.IssuedAt, nil
}

// GetAudience implements the Claims interface.
func (c RegisteredClaims) GetAudience() (jwt.ClaimStrings, error) {
	return c.Audience, nil
}

// GetIssuer implements the Claims interface.
func (c RegisteredClaims) GetIssuer() (string, error) {
	return c.Issuer, nil
}

// GetSubject implements the Claims interface.
func (c RegisteredClaims) GetSubject() (string, error) {
	return c.Subject, nil
}
