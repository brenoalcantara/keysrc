package security

import (
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	CryptoVersion = 1
	NonceSize     = chacha20poly1305.NonceSizeX
)

type EncryptedBlob struct {
	Ciphertext []byte
	Nonce      []byte
}

func GenerateVaultKey() ([]byte, error) {
	return RandomBytes(KeySize)
}

func Seal(key []byte, plaintext []byte, aad []byte) (EncryptedBlob, error) {
	aead, err := newAEAD(key)
	if err != nil {
		return EncryptedBlob{}, err
	}

	nonce, err := RandomBytes(NonceSize)
	if err != nil {
		return EncryptedBlob{}, err
	}

	ciphertext := aead.Seal(nil, nonce, plaintext, aad)
	return EncryptedBlob{
		Ciphertext: ciphertext,
		Nonce:      nonce,
	}, nil
}

func Open(key []byte, blob EncryptedBlob, aad []byte) ([]byte, error) {
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}

	if len(blob.Nonce) != NonceSize {
		return nil, fmt.Errorf("%w: nonce must be %d bytes", ErrInvalidInput, NonceSize)
	}

	if len(blob.Ciphertext) == 0 {
		return nil, fmt.Errorf("%w: ciphertext is required", ErrInvalidInput)
	}

	plaintext, err := aead.Open(nil, blob.Nonce, blob.Ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("%w: open encrypted blob", ErrAuthenticationFailed)
	}

	return plaintext, nil
}

func EncryptVaultKey(wrapKey []byte, vaultKey []byte) (EncryptedBlob, error) {
	if len(vaultKey) != KeySize {
		return EncryptedBlob{}, fmt.Errorf("%w: vault key must be %d bytes", ErrInvalidInput, KeySize)
	}

	return Seal(wrapKey, vaultKey, []byte("keysrc vault key v1"))
}

func DecryptVaultKey(wrapKey []byte, blob EncryptedBlob) ([]byte, error) {
	vaultKey, err := Open(wrapKey, blob, []byte("keysrc vault key v1"))
	if err != nil {
		return nil, err
	}

	if len(vaultKey) != KeySize {
		ZeroBytes(vaultKey)
		return nil, fmt.Errorf("%w: decrypted vault key has invalid length", ErrAuthenticationFailed)
	}

	return vaultKey, nil
}

func EncryptCredential(vaultKey []byte, credentialID string, plaintext []byte) (EncryptedBlob, error) {
	if credentialID == "" {
		return EncryptedBlob{}, fmt.Errorf("%w: credential id is required", ErrInvalidInput)
	}

	if len(plaintext) == 0 {
		return EncryptedBlob{}, fmt.Errorf("%w: credential plaintext is required", ErrInvalidInput)
	}

	return Seal(vaultKey, plaintext, CredentialAAD(credentialID, CryptoVersion))
}

func DecryptCredential(vaultKey []byte, credentialID string, blob EncryptedBlob) ([]byte, error) {
	if credentialID == "" {
		return nil, fmt.Errorf("%w: credential id is required", ErrInvalidInput)
	}

	return Open(vaultKey, blob, CredentialAAD(credentialID, CryptoVersion))
}

func CredentialAAD(credentialID string, version int) []byte {
	return []byte(fmt.Sprintf("keysrc:v%d:credentials:%s", version, credentialID))
}

func newAEAD(key []byte) (cipherAead, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("%w: key must be %d bytes", ErrInvalidInput, KeySize)
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("create xchacha20-poly1305 aead: %w", err)
	}

	return aead, nil
}

type cipherAead interface {
	Seal(dst []byte, nonce []byte, plaintext []byte, additionalData []byte) []byte
	Open(dst []byte, nonce []byte, ciphertext []byte, additionalData []byte) ([]byte, error)
}
