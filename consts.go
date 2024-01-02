package guth

type TokenType string

const (
	TokenTypeAuthToken    TokenType = "Token.Authorization"
	TokenTypeRefreshToken TokenType = "Token.Refresh"
)

const (
	AuthRejectedErrorMessage      string = "Authentication rejected."
	AuthInvalidUserErrorMessage   string = "Invalid User."
	AuthExpiredErrorMessage       string = "Authorization Token Expired."
	AuthInvalidAccessErrorMessage string = "Invalid Access to %s resources."
)

const prefix = "Bearer "
const prefixBasic = "Basic "
const prefixED25519 = "ED25519 "

const tokenTypeBearer = "Bearer"
const tokenTypeBasic = "Basic"
const tokenTypeED25519 = "ED25519"

const authorizationCookieType = "token_type"
const authorizationQueryType = "token_type"

const authorizationHeader = "Authorization"

const authorizationCookie = "jwt"
const authorizationQuery = "token"

const (
	HeaderAuthUser     = "X-Auth-User"
	HeaderAuthUserID   = "X-Auth-UserId"
	HeaderIsAuthorized = "X-Is-Authorized"

	KeyUser            = "user"
	KeyUID             = "uid"
	KeyIsAuthenticated = "is_authenticated"
)
