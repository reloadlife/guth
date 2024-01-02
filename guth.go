package guth

import "os"

func Register(secretKey, issuer string, functions ...any) {
	_ = os.Setenv("JWT_SECRET", secretKey)
	_ = os.Setenv("JWT_ISSUER", issuer)

	for _, function := range functions {
		switch function.(type) {
		case loadBySignatureFunc:
			loadBySignature = function.(loadBySignatureFunc)
		case loadByTokenFunc:
			loadByToken = function.(loadByTokenFunc)
		case loadByIDFunc:
			loadByID = function.(loadByIDFunc)
		case loadByUsernameFunc:
			loadByUsername = function.(loadByUsernameFunc)
		}
	}
}
