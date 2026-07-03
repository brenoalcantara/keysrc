package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

type vaultStore interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

type VaultRepository struct {
	store vaultStore
}

func NewVaultRepository(store vaultStore) *VaultRepository {
	return &VaultRepository{store: store}
}

func (r *VaultRepository) Exists(ctx context.Context) (bool, error) {
	var id int
	err := r.store.QueryRowContext(ctx, `SELECT id FROM vault_metadata WHERE id = 1`).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}

	if err != nil {
		return false, fmt.Errorf("check vault metadata existence: %w", err)
	}

	return true, nil
}

func (r *VaultRepository) Create(ctx context.Context, metadata VaultMetadata) error {
	if err := validateVaultMetadata(metadata); err != nil {
		return err
	}

	exists, err := r.Exists(ctx)
	if err != nil {
		return err
	}

	if exists {
		return fmt.Errorf("create vault metadata: %w", ErrAlreadyExists)
	}

	_, err = r.store.ExecContext(ctx, `INSERT INTO vault_metadata (
		id,
		schema_version,
		crypto_version,
		kdf_name,
		kdf_memory_kib,
		kdf_iterations,
		kdf_parallelism,
		kdf_salt,
		verifier,
		encrypted_vault_key,
		vault_key_nonce,
		created_at,
		updated_at
	) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		metadata.SchemaVersion,
		metadata.CryptoVersion,
		metadata.KDFName,
		metadata.KDFMemoryKiB,
		metadata.KDFIterations,
		metadata.KDFParallelism,
		metadata.KDFSalt,
		metadata.Verifier,
		metadata.EncryptedVaultKey,
		metadata.VaultKeyNonce,
		formatTimestamp(metadata.CreatedAt),
		formatTimestamp(metadata.UpdatedAt),
	)
	if err != nil {
		return fmt.Errorf("create vault metadata: %w", err)
	}

	return nil
}

func (r *VaultRepository) Get(ctx context.Context) (VaultMetadata, error) {
	var metadata VaultMetadata
	var createdAt string
	var updatedAt string

	err := r.store.QueryRowContext(ctx, `SELECT
		schema_version,
		crypto_version,
		kdf_name,
		kdf_memory_kib,
		kdf_iterations,
		kdf_parallelism,
		kdf_salt,
		verifier,
		encrypted_vault_key,
		vault_key_nonce,
		created_at,
		updated_at
	FROM vault_metadata
	WHERE id = 1`).Scan(
		&metadata.SchemaVersion,
		&metadata.CryptoVersion,
		&metadata.KDFName,
		&metadata.KDFMemoryKiB,
		&metadata.KDFIterations,
		&metadata.KDFParallelism,
		&metadata.KDFSalt,
		&metadata.Verifier,
		&metadata.EncryptedVaultKey,
		&metadata.VaultKeyNonce,
		&createdAt,
		&updatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return VaultMetadata{}, fmt.Errorf("get vault metadata: %w", ErrNotFound)
	}

	if err != nil {
		return VaultMetadata{}, fmt.Errorf("get vault metadata: %w", err)
	}

	metadata.CreatedAt, err = parseTimestamp("created_at", createdAt)
	if err != nil {
		return VaultMetadata{}, err
	}

	metadata.UpdatedAt, err = parseTimestamp("updated_at", updatedAt)
	if err != nil {
		return VaultMetadata{}, err
	}

	metadata.KDFSalt = cloneBytes(metadata.KDFSalt)
	metadata.Verifier = cloneBytes(metadata.Verifier)
	metadata.EncryptedVaultKey = cloneBytes(metadata.EncryptedVaultKey)
	metadata.VaultKeyNonce = cloneBytes(metadata.VaultKeyNonce)

	return metadata, nil
}

func (r *VaultRepository) Update(ctx context.Context, metadata VaultMetadata) error {
	if err := validateVaultMetadata(metadata); err != nil {
		return err
	}

	result, err := r.store.ExecContext(ctx, `UPDATE vault_metadata SET
		schema_version = ?,
		crypto_version = ?,
		kdf_name = ?,
		kdf_memory_kib = ?,
		kdf_iterations = ?,
		kdf_parallelism = ?,
		kdf_salt = ?,
		verifier = ?,
		encrypted_vault_key = ?,
		vault_key_nonce = ?,
		created_at = ?,
		updated_at = ?
	WHERE id = 1`,
		metadata.SchemaVersion,
		metadata.CryptoVersion,
		metadata.KDFName,
		metadata.KDFMemoryKiB,
		metadata.KDFIterations,
		metadata.KDFParallelism,
		metadata.KDFSalt,
		metadata.Verifier,
		metadata.EncryptedVaultKey,
		metadata.VaultKeyNonce,
		formatTimestamp(metadata.CreatedAt),
		formatTimestamp(metadata.UpdatedAt),
	)
	if err != nil {
		return fmt.Errorf("update vault metadata: %w", err)
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("update vault metadata rows affected: %w", err)
	}

	if affected == 0 {
		return fmt.Errorf("update vault metadata: %w", ErrNotFound)
	}

	return nil
}

func validateVaultMetadata(metadata VaultMetadata) error {
	switch {
	case metadata.SchemaVersion <= 0:
		return fmt.Errorf("%w: schema version must be positive", ErrInvalidRecord)
	case metadata.CryptoVersion <= 0:
		return fmt.Errorf("%w: crypto version must be positive", ErrInvalidRecord)
	case metadata.KDFName == "":
		return fmt.Errorf("%w: kdf name is required", ErrInvalidRecord)
	case metadata.KDFMemoryKiB <= 0:
		return fmt.Errorf("%w: kdf memory must be positive", ErrInvalidRecord)
	case metadata.KDFIterations <= 0:
		return fmt.Errorf("%w: kdf iterations must be positive", ErrInvalidRecord)
	case metadata.KDFParallelism <= 0:
		return fmt.Errorf("%w: kdf parallelism must be positive", ErrInvalidRecord)
	case len(metadata.KDFSalt) == 0:
		return fmt.Errorf("%w: kdf salt is required", ErrInvalidRecord)
	case len(metadata.Verifier) == 0:
		return fmt.Errorf("%w: verifier is required", ErrInvalidRecord)
	case len(metadata.EncryptedVaultKey) == 0:
		return fmt.Errorf("%w: encrypted vault key is required", ErrInvalidRecord)
	case len(metadata.VaultKeyNonce) == 0:
		return fmt.Errorf("%w: vault key nonce is required", ErrInvalidRecord)
	case metadata.CreatedAt.IsZero():
		return fmt.Errorf("%w: created_at is required", ErrInvalidRecord)
	case metadata.UpdatedAt.IsZero():
		return fmt.Errorf("%w: updated_at is required", ErrInvalidRecord)
	case metadata.UpdatedAt.Before(metadata.CreatedAt):
		return fmt.Errorf("%w: updated_at cannot be before created_at", ErrInvalidRecord)
	default:
		return nil
	}
}
