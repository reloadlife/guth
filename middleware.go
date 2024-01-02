package guth

import (
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
)

func optionalReject(o bool, c *gin.Context) {
	if o {
		c.Header("X-Auth-User", "GuestUser")
		c.Header("X-Auth-UserId", "0")
		c.Header("X-Is-Authorized", "0")

		c.Set("login", false)
		c.Set("uid", uint(0))
		c.Next()
		return
	}
	c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"message": AuthRejectedErrorMessage})
}

func extractToken(c *gin.Context) (tokenType, token string) {
	_authHeader := c.GetHeader(authorizationHeader)
	if _authHeader != "" {
		token = strings.TrimSpace(_authHeader)
	}

	if token == "" {
		_authQuery := c.Query(authorizationQuery)
		tokenType = c.Query(authorizationQueryType)
		if tokenType == "" {
			tokenType = tokenTypeBearer
		}
		if _authQuery != "" {
			token = tokenType + " " + strings.TrimSpace(_authQuery)
		}
	}

	if token == "" {
		_authCookie, _ := c.Cookie(authorizationCookie)

		tokenType, _ = c.Cookie(authorizationCookieType)
		if tokenType == "" {
			tokenType = tokenTypeBearer
		}
		if _authCookie != "" {
			token = tokenType + " " + strings.TrimSpace(_authCookie)
		}
	}

	if len(token) > len(prefix) {
		if strings.EqualFold(token[:len(prefix)], prefix) {
			token = token[len(prefix):]
			tokenType = tokenTypeBearer
			return
		}
	}
	if len(token) > len(prefixBasic) {
		if strings.EqualFold(token[:len(prefixBasic)], prefixBasic) {
			token = token[len(prefixBasic):]
			tokenType = tokenTypeBasic
			return
		}
	}

	if len(token) > len(prefixED25519) {
		if strings.EqualFold(token[:len(prefixED25519)], prefixED25519) {
			token = token[len(prefixED25519):]
			tokenType = tokenTypeED25519
			return
		}
	}

	return "", ""
}

func loginAs(user AuthorizeUser, authId *uint64, c *gin.Context, roles ...any) {
	if user == nil {
		log.Printf("loginAs: User is nil, load the user before passing it to loginAs.")
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"message": AuthInvalidUserErrorMessage})
		return
	}

	if authId != nil && *authId != 0 {
		if !user.IsValidDeviceID(*authId) {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"message": AuthExpiredErrorMessage})
			return
		}
	}

	c.Header(HeaderAuthUser, user.GetName())
	c.Header(HeaderAuthUserID, strconv.FormatUint(user.GetID(), 10))
	c.Header(HeaderIsAuthorized, "1")

	c.Set(KeyUser, user)
	c.Set(KeyUID, user.GetID())
	c.Set(KeyIsAuthenticated, true)

	// User is authenticated, but not authorized.
	if len(roles) > 0 {
		for _, role := range roles {
			switch role.(type) {
			case string:
				if !user.HasRoleAccess(role.(string)) {
					c.AbortWithStatusJSON(http.StatusUnauthorized,
						gin.H{"message": fmt.Sprintf(AuthInvalidAccessErrorMessage, role)})
					return
				}

			case []string:
				hasOne := false
				for _, r := range role.([]string) {
					if user.HasRoleAccess(r) {
						hasOne = true
						break
					}
				}
				if !hasOne {
					c.AbortWithStatusJSON(http.StatusUnauthorized,
						gin.H{"message": fmt.Sprintf(AuthInvalidAccessErrorMessage, role)})
					return
				}
			}
		}
	}

	c.Next()
}

func Authenticate(optional bool, roles ...any) gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenType, token := extractToken(c)
		_, _, hasBasic := c.Request.BasicAuth()

		switch tokenType {

		case tokenTypeED25519:
			e, err := loadByToken(token)
			if e != nil && err == nil {
				loginAs(e, nil, c, roles...)
				return
			}

		case tokenTypeBearer:
			id, authId, _, err := VerifyAuthToken(token)
			if err == nil {
				numId, _ := strconv.ParseUint(id, 10, 64)
				user, _ := loadByID(numId)
				loginAs(user, authId, c, roles...)
				return
			}

		case tokenTypeBasic:
			if hasBasic {
				bytes, err := base64.StdEncoding.DecodeString(token)
				if err == nil {
					username, password, ok := strings.Cut(string(bytes), ":")
					if ok {
						user, _ := loadByUsername(username)
						if user != nil && user.CheckPassword(password) {
							authId := uint64(0)
							loginAs(user, &authId, c, roles...)
							return
						}
					}
				}
			}
		}

		optionalReject(optional, c)
	}
}
