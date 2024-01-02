package guth

type AuthorizeUser interface {
	// GetName Displayed name of the User.
	GetName() string
	GetID() uint64
	CheckPassword(password string) bool
	HasRoleAccess(role string) bool
	IsValidDeviceID(deviceID uint64) bool
	// IsValidSignature works by checking the signature against the user's GetID().
	IsValidSignature(signature string) bool
}

type loadByTokenFunc func(token string) (AuthorizeUser, error)
type loadByIDFunc func(id uint64) (AuthorizeUser, error)
type loadByUsernameFunc func(username string) (AuthorizeUser, error)
type loadBySignatureFunc func(signature string) (AuthorizeUser, error)

var loadByToken loadByTokenFunc
var loadByID loadByIDFunc
var loadByUsername loadByUsernameFunc
var loadBySignature loadBySignatureFunc
