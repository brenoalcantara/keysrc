package security

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"runtime"

	"golang.org/x/crypto/argon2"
)

const (
	KeySize                = 32
	MinimumKDFMemoryKiB    = 1024
	MinimumKDFSaltLength   = 16
	DefaultKDFMemoryKiB    = 64 * 1024
	DefaultKDFIterations   = 3
	DefaultKDFSaltLength   = 16
	DefaultKDFKeyLength    = KeySize
	maximumKDFParallelism  = 4
	hkdfHashLength         = sha256.Size
	hkdfMaximumOutputBytes = 255 * hkdfHashLength
)

var hkdfSalt = []byte("keysrc security v1")

type KDFParams struct {
	MemoryKiB   uint32
	Iterations  uint32
	Parallelism uint8
	SaltLength  int
	KeyLength   uint32
}

type Subkeys struct {
	WrapKey []byte
	AuthKey []byte
}

func DefaultKDFParams() KDFParams {
	parallelism := runtime.NumCPU()
	if parallelism < 1 {
		parallelism = 1
	}

	if parallelism > maximumKDFParallelism {
		parallelism = maximumKDFParallelism
	}

	return KDFParams{
		MemoryKiB:   DefaultKDFMemoryKiB,
		Iterations:  DefaultKDFIterations,
		Parallelism: uint8(parallelism),
		SaltLength:  DefaultKDFSaltLength,
		KeyLength:   DefaultKDFKeyLength,
	}
}

func ValidateKDFParams(params KDFParams) error {
	switch {
	case params.MemoryKiB < MinimumKDFMemoryKiB:
		return fmt.Errorf("%w: kdf memory must be at least %d KiB", ErrInvalidInput, MinimumKDFMemoryKiB)
	case params.Iterations == 0:
		return fmt.Errorf("%w: kdf iterations must be positive", ErrInvalidInput)
	case params.Parallelism == 0:
		return fmt.Errorf("%w: kdf parallelism must be positive", ErrInvalidInput)
	case params.KeyLength != KeySize:
		return fmt.Errorf("%w: kdf key length must be %d bytes", ErrInvalidInput, KeySize)
	default:
		return nil
	}
}

func ValidateKDFParamsForCreation(params KDFParams) error {
	if err := ValidateKDFParams(params); err != nil {
		return err
	}

	if params.SaltLength < MinimumKDFSaltLength {
		return fmt.Errorf("%w: kdf salt length must be at least %d bytes", ErrInvalidInput, MinimumKDFSaltLength)
	}

	return nil
}

func GenerateSalt(params KDFParams) ([]byte, error) {
	if err := ValidateKDFParamsForCreation(params); err != nil {
		return nil, err
	}

	return RandomBytes(params.SaltLength)
}

func DeriveMasterKey(password []byte, salt []byte, params KDFParams) ([]byte, error) {
	if len(password) == 0 {
		return nil, fmt.Errorf("%w: password is required", ErrInvalidInput)
	}

	if len(salt) < MinimumKDFSaltLength {
		return nil, fmt.Errorf("%w: kdf salt must be at least %d bytes", ErrInvalidInput, MinimumKDFSaltLength)
	}

	if err := ValidateKDFParams(params); err != nil {
		return nil, err
	}

	key := argon2.IDKey(password, salt, params.Iterations, params.MemoryKiB, params.Parallelism, params.KeyLength)
	return key, nil
}

func DeriveSubkeys(masterKey []byte) (Subkeys, error) {
	if len(masterKey) != KeySize {
		return Subkeys{}, fmt.Errorf("%w: master key must be %d bytes", ErrInvalidInput, KeySize)
	}

	wrapKey, err := deriveHKDF(masterKey, "keysrc wrap key v1", KeySize)
	if err != nil {
		return Subkeys{}, err
	}

	authKey, err := deriveHKDF(masterKey, "keysrc auth key v1", KeySize)
	if err != nil {
		ZeroBytes(wrapKey)
		return Subkeys{}, err
	}

	return Subkeys{
		WrapKey: wrapKey,
		AuthKey: authKey,
	}, nil
}

func deriveHKDF(inputKey []byte, info string, length int) ([]byte, error) {
	if len(inputKey) == 0 {
		return nil, fmt.Errorf("%w: hkdf input key is required", ErrInvalidInput)
	}

	if info == "" {
		return nil, fmt.Errorf("%w: hkdf info is required", ErrInvalidInput)
	}

	if length <= 0 || length > hkdfMaximumOutputBytes {
		return nil, fmt.Errorf("%w: invalid hkdf output length", ErrInvalidInput)
	}

	prk := hkdfExtract(hkdfSalt, inputKey)
	defer ZeroBytes(prk)

	return hkdfExpand(prk, []byte(info), length)
}

func hkdfExtract(salt []byte, inputKey []byte) []byte {
	mac := hmac.New(sha256.New, salt)
	mac.Write(inputKey)
	return mac.Sum(nil)
}

func hkdfExpand(pseudorandomKey []byte, info []byte, length int) ([]byte, error) {
	var output []byte
	var previous []byte

	for counter := byte(1); len(output) < length; counter++ {
		mac := hmac.New(sha256.New, pseudorandomKey)
		mac.Write(previous)
		mac.Write(info)
		mac.Write([]byte{counter})
		previous = mac.Sum(nil)
		output = append(output, previous...)
	}

	return cloneBytes(output[:length]), nil
}

func CreateVerifier(authKey []byte) ([]byte, error) {
	if len(authKey) != KeySize {
		return nil, fmt.Errorf("%w: auth key must be %d bytes", ErrInvalidInput, KeySize)
	}

	mac := hmac.New(sha256.New, authKey)
	mac.Write([]byte("keysrc master password verifier v1"))
	return mac.Sum(nil), nil
}

func VerifyVerifier(authKey []byte, expected []byte) bool {
	if len(authKey) != KeySize || len(expected) != sha256.Size {
		return false
	}

	actual, err := CreateVerifier(authKey)
	if err != nil {
		return false
	}
	defer ZeroBytes(actual)

	return hmac.Equal(actual, expected)
}

func (s Subkeys) Zero() {
	ZeroBytes(s.WrapKey)
	ZeroBytes(s.AuthKey)
}
