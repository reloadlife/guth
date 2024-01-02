package guth

import (
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"strconv"
	"time"
)

func GenerateAuthToken(userId uint, tokenExpire time.Duration, authID ...uint64) (authToken string, err error) {
	return generateToken(TokenTypeAuthToken, strconv.Itoa(int(userId)), tokenExpire, authID...)
}

func GenerateRefreshToken(userId uint, refreshTokenExpire time.Duration, authID ...uint64) (refreshToken string, err error) {
	return generateToken(TokenTypeRefreshToken, strconv.Itoa(int(userId)), refreshTokenExpire, authID...)
}

func VerifyAuthToken(token string) (ID string, authId *uint64, claims *RegisteredClaims, err error) {
	return verifyToken(token, TokenTypeAuthToken)
}

func VerifyRefreshToken(token string) (ID int64, err error) {
	str, _, _, err := verifyToken(token, TokenTypeRefreshToken)
	if err != nil {
		return 0, err
	}
	return strconv.ParseInt(str, 10, 64)
}

func VerifyTokenWithInformation(token string) (*RegisteredClaims, error) {
	load()

	claims := &RegisteredClaims{}

	verifiedToken, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("bad signture: %v", token.Header["alg"])
		}
		return []byte(jwtSecretKey), nil
	})

	if err != nil {
		return nil, err
	}

	return verifiedToken.Claims.(*RegisteredClaims), nil
}
