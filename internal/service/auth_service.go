package service

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"keysrc/internal/security"
	"keysrc/internal/storage"
)

const kdfNameArgon2id = "argon2id"

const (
	maxUint8AsInt  = 255
	maxUint32AsInt = int(^uint32(0))
)

type AuthService struct {
	db             *sql.DB
	kdfParams      security.KDFParams
	passwordPolicy security.MasterPasswordPolicy
	now            func() time.Time
}

type AuthOptions struct {
	KDFParams      security.KDFParams
	PasswordPolicy security.MasterPasswordPolicy
	Now            func() time.Time
}

type VaultSession struct {
	VaultKey   []byte
	UnlockedAt time.Time
}

func NewAuthService(db *sql.DB) *AuthService {
	return NewAuthServiceWithOptions(db, AuthOptions{})
}

func NewAuthServiceWithOptions(db *sql.DB, options AuthOptions) *AuthService {
	kdfParams := options.KDFParams
	if kdfParams == (security.KDFParams{}) {
		kdfParams = security.DefaultKDFParams()
	}

	passwordPolicy := options.PasswordPolicy
	if passwordPolicy == (security.MasterPasswordPolicy{}) {
		passwordPolicy = security.DefaultMasterPasswordPolicy()
	}

	now := options.Now
	if now == nil {
		now = time.Now
	}

	return &AuthService{
		db:             db,
		kdfParams:      kdfParams,
		passwordPolicy: passwordPolicy,
		now:            now,
	}
}

func (s *AuthService) HasVault(ctx context.Context) (bool, error) {
	if s.db == nil {
		return false, fmt.Errorf("check vault: %w", storage.ErrInvalidRecord)
	}

	return storage.NewVaultRepository(s.db).Exists(ctx)
}

func (s *AuthService) CreateVault(ctx context.Context, masterPassword []byte) (*VaultSession, error) {
	if s.db == nil {
		return nil, fmt.Errorf("create vault: %w", storage.ErrInvalidRecord)
	}

	if err := security.ValidateMasterPasswordBytes(masterPassword, s.passwordPolicy); err != nil {
		return nil, err
	}

	exists, err := s.HasVault(ctx)
	if err != nil {
		return nil, err
	}

	if exists {
		return nil, fmt.Errorf("create vault: %w", storage.ErrAlreadyExists)
	}

	envelope, vaultKey, err := security.NewVaultEnvelope(masterPassword, s.kdfParams)
	if err != nil {
		return nil, err
	}

	createdAt := s.now().UTC()
	metadata := metadataFromEnvelope(envelope, createdAt, createdAt)

	if err := storage.WithinTx(ctx, s.db, func(tx *sql.Tx) error {
		return storage.NewVaultRepository(tx).Create(ctx, metadata)
	}); err != nil {
		security.ZeroBytes(vaultKey)
		return nil, err
	}

	return &VaultSession{
		VaultKey:   vaultKey,
		UnlockedAt: createdAt,
	}, nil
}

func (s *AuthService) UnlockVault(ctx context.Context, masterPassword []byte) (*VaultSession, error) {
	if s.db == nil {
		return nil, fmt.Errorf("unlock vault: %w", storage.ErrInvalidRecord)
	}

	metadata, err := storage.NewVaultRepository(s.db).Get(ctx)
	if err != nil {
		return nil, err
	}

	envelope, err := envelopeFromMetadata(metadata)
	if err != nil {
		return nil, err
	}

	vaultKey, err := security.OpenVaultEnvelope(masterPassword, envelope)
	if err != nil {
		return nil, err
	}

	return &VaultSession{
		VaultKey:   vaultKey,
		UnlockedAt: s.now().UTC(),
	}, nil
}

func (s *AuthService) ChangeMasterPassword(ctx context.Context, currentPassword []byte, newPassword []byte) (*VaultSession, error) {
	if s.db == nil {
		return nil, fmt.Errorf("change master password: %w", storage.ErrInvalidRecord)
	}

	if err := security.ValidateMasterPasswordBytes(newPassword, s.passwordPolicy); err != nil {
		return nil, err
	}

	var vaultKey []byte
	var unlockedAt time.Time
	err := storage.WithinTx(ctx, s.db, func(tx *sql.Tx) error {
		repo := storage.NewVaultRepository(tx)

		metadata, err := repo.Get(ctx)
		if err != nil {
			return err
		}

		currentEnvelope, err := envelopeFromMetadata(metadata)
		if err != nil {
			return err
		}

		openedVaultKey, err := security.OpenVaultEnvelope(currentPassword, currentEnvelope)
		if err != nil {
			return err
		}

		newEnvelope, err := security.NewVaultEnvelopeForVaultKey(newPassword, s.kdfParams, openedVaultKey)
		if err != nil {
			security.ZeroBytes(openedVaultKey)
			return err
		}

		updatedAt := s.now().UTC()
		updatedMetadata := metadataFromEnvelope(newEnvelope, metadata.CreatedAt, updatedAt)
		if err := repo.Update(ctx, updatedMetadata); err != nil {
			security.ZeroBytes(openedVaultKey)
			return err
		}

		vaultKey = openedVaultKey
		unlockedAt = updatedAt
		return nil
	})
	if err != nil {
		security.ZeroBytes(vaultKey)
		return nil, err
	}

	return &VaultSession{
		VaultKey:   vaultKey,
		UnlockedAt: unlockedAt,
	}, nil
}

func (s *VaultSession) Lock() {
	if s == nil {
		return
	}

	security.ZeroBytes(s.VaultKey)
	s.VaultKey = nil
}

func metadataFromEnvelope(envelope security.VaultEnvelope, createdAt time.Time, updatedAt time.Time) storage.VaultMetadata {
	return storage.VaultMetadata{
		SchemaVersion:     storage.CurrentSchemaVersion,
		CryptoVersion:     security.CryptoVersion,
		KDFName:           kdfNameArgon2id,
		KDFMemoryKiB:      int(envelope.KDFParams.MemoryKiB),
		KDFIterations:     int(envelope.KDFParams.Iterations),
		KDFParallelism:    int(envelope.KDFParams.Parallelism),
		KDFSalt:           cloneBytes(envelope.KDFSalt),
		Verifier:          cloneBytes(envelope.Verifier),
		EncryptedVaultKey: cloneBytes(envelope.EncryptedVaultKey),
		VaultKeyNonce:     cloneBytes(envelope.VaultKeyNonce),
		CreatedAt:         createdAt,
		UpdatedAt:         updatedAt,
	}
}

func envelopeFromMetadata(metadata storage.VaultMetadata) (security.VaultEnvelope, error) {
	if metadata.CryptoVersion != security.CryptoVersion {
		return security.VaultEnvelope{}, fmt.Errorf("unsupported crypto version %d", metadata.CryptoVersion)
	}

	if metadata.KDFName != kdfNameArgon2id {
		return security.VaultEnvelope{}, fmt.Errorf("unsupported kdf %q", metadata.KDFName)
	}

	if metadata.KDFMemoryKiB <= 0 || metadata.KDFMemoryKiB > maxUint32AsInt {
		return security.VaultEnvelope{}, fmt.Errorf("invalid kdf memory %d", metadata.KDFMemoryKiB)
	}

	if metadata.KDFIterations <= 0 || metadata.KDFIterations > maxUint32AsInt {
		return security.VaultEnvelope{}, fmt.Errorf("invalid kdf iterations %d", metadata.KDFIterations)
	}

	if metadata.KDFParallelism <= 0 || metadata.KDFParallelism > maxUint8AsInt {
		return security.VaultEnvelope{}, fmt.Errorf("invalid kdf parallelism %d", metadata.KDFParallelism)
	}

	return security.VaultEnvelope{
		KDFParams: security.KDFParams{
			MemoryKiB:   uint32(metadata.KDFMemoryKiB),
			Iterations:  uint32(metadata.KDFIterations),
			Parallelism: uint8(metadata.KDFParallelism),
			SaltLength:  len(metadata.KDFSalt),
			KeyLength:   security.KeySize,
		},
		KDFSalt:           cloneBytes(metadata.KDFSalt),
		Verifier:          cloneBytes(metadata.Verifier),
		EncryptedVaultKey: cloneBytes(metadata.EncryptedVaultKey),
		VaultKeyNonce:     cloneBytes(metadata.VaultKeyNonce),
	}, nil
}

func cloneBytes(value []byte) []byte {
	if value == nil {
		return nil
	}

	cloned := make([]byte, len(value))
	copy(cloned, value)
	return cloned
}
