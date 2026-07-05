package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

type credentialStore interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

type CredentialRepository struct {
	store credentialStore
}

func NewCredentialRepository(store credentialStore) *CredentialRepository {
	return &CredentialRepository{store: store}
}

func (r *CredentialRepository) Create(ctx context.Context, record CredentialRecord) error {
	if err := validateCredentialRecord(record); err != nil {
		return err
	}

	_, err := r.store.ExecContext(ctx, `INSERT INTO credentials (
		id,
		ciphertext,
		nonce,
		aad_version,
		created_at,
		updated_at,
		deleted_at
	) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		record.ID,
		record.Ciphertext,
		record.Nonce,
		record.AADVersion,
		formatTimestamp(record.CreatedAt),
		formatTimestamp(record.UpdatedAt),
		formatNullableTimestamp(record.DeletedAt),
	)
	if err != nil {
		return fmt.Errorf("create credential: %w", err)
	}

	return nil
}

func (r *CredentialRepository) Get(ctx context.Context, id string) (CredentialRecord, error) {
	var record CredentialRecord
	var createdAt string
	var updatedAt string
	var deletedAt sql.NullString

	err := r.store.QueryRowContext(ctx, `SELECT
		id,
		ciphertext,
		nonce,
		aad_version,
		created_at,
		updated_at,
		deleted_at
	FROM credentials
	WHERE id = ?`, id).Scan(
		&record.ID,
		&record.Ciphertext,
		&record.Nonce,
		&record.AADVersion,
		&createdAt,
		&updatedAt,
		&deletedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return CredentialRecord{}, fmt.Errorf("get credential: %w", ErrNotFound)
	}

	if err != nil {
		return CredentialRecord{}, fmt.Errorf("get credential: %w", err)
	}

	if err := hydrateCredentialTimestamps(&record, createdAt, updatedAt, deletedAt); err != nil {
		return CredentialRecord{}, err
	}

	record.Ciphertext = cloneBytes(record.Ciphertext)
	record.Nonce = cloneBytes(record.Nonce)

	return record, nil
}

func (r *CredentialRepository) ListActive(ctx context.Context) (records []CredentialRecord, err error) {
	rows, err := r.store.QueryContext(ctx, `SELECT
		id,
		ciphertext,
		nonce,
		aad_version,
		created_at,
		updated_at,
		deleted_at
	FROM credentials
	WHERE deleted_at IS NULL
	ORDER BY updated_at DESC, id ASC`)
	if err != nil {
		return nil, fmt.Errorf("list active credentials: %w", err)
	}
	defer func() {
		if closeErr := rows.Close(); err == nil && closeErr != nil {
			err = fmt.Errorf("close active credentials rows: %w", closeErr)
		}
	}()

	for rows.Next() {
		var record CredentialRecord
		var createdAt string
		var updatedAt string
		var deletedAt sql.NullString

		if err := rows.Scan(
			&record.ID,
			&record.Ciphertext,
			&record.Nonce,
			&record.AADVersion,
			&createdAt,
			&updatedAt,
			&deletedAt,
		); err != nil {
			return nil, fmt.Errorf("scan active credential: %w", err)
		}

		if err := hydrateCredentialTimestamps(&record, createdAt, updatedAt, deletedAt); err != nil {
			return nil, err
		}

		record.Ciphertext = cloneBytes(record.Ciphertext)
		record.Nonce = cloneBytes(record.Nonce)
		records = append(records, record)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate active credentials: %w", err)
	}

	return records, nil
}

func (r *CredentialRepository) Update(ctx context.Context, record CredentialRecord) error {
	if err := validateCredentialRecord(record); err != nil {
		return err
	}

	result, err := r.store.ExecContext(ctx, `UPDATE credentials SET
		ciphertext = ?,
		nonce = ?,
		aad_version = ?,
		created_at = ?,
		updated_at = ?,
		deleted_at = ?
	WHERE id = ?`,
		record.Ciphertext,
		record.Nonce,
		record.AADVersion,
		formatTimestamp(record.CreatedAt),
		formatTimestamp(record.UpdatedAt),
		formatNullableTimestamp(record.DeletedAt),
		record.ID,
	)
	if err != nil {
		return fmt.Errorf("update credential: %w", err)
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("update credential rows affected: %w", err)
	}

	if affected == 0 {
		return fmt.Errorf("update credential: %w", ErrNotFound)
	}

	return nil
}

func (r *CredentialRepository) SoftDelete(ctx context.Context, id string, deletedAt time.Time) error {
	if id == "" {
		return fmt.Errorf("%w: id is required", ErrInvalidRecord)
	}

	if deletedAt.IsZero() {
		return fmt.Errorf("%w: deleted_at is required", ErrInvalidRecord)
	}

	result, err := r.store.ExecContext(ctx, `UPDATE credentials SET
		updated_at = ?,
		deleted_at = ?
	WHERE id = ?`,
		formatTimestamp(deletedAt),
		formatTimestamp(deletedAt),
		id,
	)
	if err != nil {
		return fmt.Errorf("soft delete credential: %w", err)
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("soft delete credential rows affected: %w", err)
	}

	if affected == 0 {
		return fmt.Errorf("soft delete credential: %w", ErrNotFound)
	}

	return nil
}

func hydrateCredentialTimestamps(record *CredentialRecord, createdAt string, updatedAt string, deletedAt sql.NullString) error {
	var err error

	record.CreatedAt, err = parseTimestamp("created_at", createdAt)
	if err != nil {
		return err
	}

	record.UpdatedAt, err = parseTimestamp("updated_at", updatedAt)
	if err != nil {
		return err
	}

	record.DeletedAt, err = parseNullableTimestamp("deleted_at", deletedAt)
	if err != nil {
		return err
	}

	return nil
}

func validateCredentialRecord(record CredentialRecord) error {
	switch {
	case record.ID == "":
		return fmt.Errorf("%w: id is required", ErrInvalidRecord)
	case len(record.Ciphertext) == 0:
		return fmt.Errorf("%w: ciphertext is required", ErrInvalidRecord)
	case len(record.Nonce) == 0:
		return fmt.Errorf("%w: nonce is required", ErrInvalidRecord)
	case record.AADVersion <= 0:
		return fmt.Errorf("%w: aad version must be positive", ErrInvalidRecord)
	case record.CreatedAt.IsZero():
		return fmt.Errorf("%w: created_at is required", ErrInvalidRecord)
	case record.UpdatedAt.IsZero():
		return fmt.Errorf("%w: updated_at is required", ErrInvalidRecord)
	case record.UpdatedAt.Before(record.CreatedAt):
		return fmt.Errorf("%w: updated_at cannot be before created_at", ErrInvalidRecord)
	case record.DeletedAt != nil && record.DeletedAt.Before(record.CreatedAt):
		return fmt.Errorf("%w: deleted_at cannot be before created_at", ErrInvalidRecord)
	default:
		return nil
	}
}
