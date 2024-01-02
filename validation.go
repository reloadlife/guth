package guth

import (
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"time"
)

func verifyToken(token string, subject TokenType) (ID string, AuthId *uint64, claims *RegisteredClaims, err error) {
	load()

	claims = &RegisteredClaims{}

	verifiedToken, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("bad signture: %v", token.Header["alg"])
		}
		return []byte(jwtSecretKey), nil
	})

	if err != nil {
		return "", nil, nil, err
	}

	claims, ok := verifiedToken.Claims.(*RegisteredClaims)

	if ok && verifiedToken.Valid {
		if claims.ExpiresAt.Time.Before(time.Now()) {
			return "", nil, nil, errors.New("expired token")
		}

		if claims.Issuer != issuer {
			return "", nil, nil, errors.New("invalid token issuer")
		}

		if claims.Subject != string(subject) {
			return "", nil, nil, errors.New("invalid token subject")
		}

		return claims.ID, claims.AuthID, claims, nil
	}

	return "", nil, nil, errors.New("failed to verify token")
}
