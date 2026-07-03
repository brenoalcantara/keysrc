package storage

import "time"

type VaultMetadata struct {
	SchemaVersion     int
	CryptoVersion     int
	KDFName           string
	KDFMemoryKiB      int
	KDFIterations     int
	KDFParallelism    int
	KDFSalt           []byte
	Verifier          []byte
	EncryptedVaultKey []byte
	VaultKeyNonce     []byte
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

type CredentialRecord struct {
	ID         string
	Ciphertext []byte
	Nonce      []byte
	AADVersion int
	CreatedAt  time.Time
	UpdatedAt  time.Time
	DeletedAt  *time.Time
}
