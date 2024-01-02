package guth

import "os"

var (
	jwtSecretKey = ""
	issuer       = ""
)

func load() {
	_ = getSecretKey()
	issuerLoad()
}

func getSecretKey() string {
	if jwtSecretKey != "" {
		return jwtSecretKey
	}
	secretKey, ok := os.LookupEnv("JWT_SECRET")
	if !ok {
		panic("JWT_SECRET not set")
	}
	jwtSecretKey = secretKey
	return secretKey
}

func issuerLoad() {
	issuer_, ok := os.LookupEnv("JWT_ISSUER")
	if ok {
		issuer = issuer_
	}
}

func GetIssuer() string {
	return issuer
}
