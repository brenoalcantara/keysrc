package storage

import "errors"

var (
	ErrAlreadyExists = errors.New("storage: already exists")
	ErrInvalidRecord = errors.New("storage: invalid record")
	ErrNotFound      = errors.New("storage: not found")
)
