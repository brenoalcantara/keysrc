package security

import "errors"

var (
	ErrAuthenticationFailed = errors.New("security: authentication failed")
	ErrInvalidInput         = errors.New("security: invalid input")
	ErrWeakPassword         = errors.New("security: weak password")
)
