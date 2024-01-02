package guth

import (
	"errors"
	"github.com/golang-jwt/jwt/v5"
	"time"
)

func generateToken(subject TokenType, ID string, expiresAt time.Duration, authID ...uint64) (string, error) {
	load()
	var aid *uint64
	if len(authID) > 0 {
		aid = &authID[0]
	}

	claims := RegisteredClaims{
		Issuer:    GetIssuer(),
		Subject:   string(subject),
		Audience:  []string{"api", "oauth2.0"},
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(expiresAt)),
		NotBefore: jwt.NewNumericDate(time.Now().Add(-1 * time.Minute)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		ID:        ID,
		AuthID:    aid,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS384, claims)
	signedString, err := token.SignedString([]byte(jwtSecretKey))
	if err == nil {
		return signedString, nil
	}

	return "", errors.Join(errors.New("token generation failed"), err)
}
