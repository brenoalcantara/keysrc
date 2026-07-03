package storage

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

const CurrentSchemaVersion = 1

type migration struct {
	Version    int
	Name       string
	Statements []string
}

var migrations = []migration{
	{
		Version: 1,
		Name:    "create_vault_and_credentials_tables",
		Statements: []string{
			`CREATE TABLE vault_metadata (
				id INTEGER PRIMARY KEY CHECK (id = 1),
				schema_version INTEGER NOT NULL CHECK (schema_version > 0),
				crypto_version INTEGER NOT NULL CHECK (crypto_version > 0),
				kdf_name TEXT NOT NULL CHECK (length(kdf_name) > 0),
				kdf_memory_kib INTEGER NOT NULL CHECK (kdf_memory_kib > 0),
				kdf_iterations INTEGER NOT NULL CHECK (kdf_iterations > 0),
				kdf_parallelism INTEGER NOT NULL CHECK (kdf_parallelism > 0),
				kdf_salt BLOB NOT NULL CHECK (length(kdf_salt) > 0),
				verifier BLOB NOT NULL CHECK (length(verifier) > 0),
				encrypted_vault_key BLOB NOT NULL CHECK (length(encrypted_vault_key) > 0),
				vault_key_nonce BLOB NOT NULL CHECK (length(vault_key_nonce) > 0),
				created_at TEXT NOT NULL CHECK (length(created_at) > 0),
				updated_at TEXT NOT NULL CHECK (length(updated_at) > 0)
			)`,
			`CREATE TABLE credentials (
				id TEXT PRIMARY KEY CHECK (length(id) > 0),
				ciphertext BLOB NOT NULL CHECK (length(ciphertext) > 0),
				nonce BLOB NOT NULL CHECK (length(nonce) > 0),
				aad_version INTEGER NOT NULL CHECK (aad_version > 0),
				created_at TEXT NOT NULL CHECK (length(created_at) > 0),
				updated_at TEXT NOT NULL CHECK (length(updated_at) > 0),
				deleted_at TEXT
			)`,
			`CREATE INDEX credentials_active_updated_at_idx
				ON credentials(deleted_at, updated_at DESC)`,
			`CREATE TABLE security_events (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				event_type TEXT NOT NULL CHECK (length(event_type) > 0),
				created_at TEXT NOT NULL CHECK (length(created_at) > 0)
			)`,
			`PRAGMA user_version = 1`,
		},
	},
}

func Migrate(ctx context.Context, db *sql.DB) error {
	if db == nil {
		return fmt.Errorf("migrate database: %w", ErrInvalidRecord)
	}

	return WithinTx(ctx, db, func(tx *sql.Tx) error {
		if err := ensureSchemaMigrationsTable(ctx, tx); err != nil {
			return err
		}

		applied, err := appliedMigrationVersions(ctx, tx)
		if err != nil {
			return err
		}

		for _, migration := range migrations {
			if applied[migration.Version] {
				continue
			}

			for _, statement := range migration.Statements {
				if _, err := tx.ExecContext(ctx, statement); err != nil {
					return fmt.Errorf("apply migration %d %s: %w", migration.Version, migration.Name, err)
				}
			}

			if _, err := tx.ExecContext(
				ctx,
				`INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)`,
				migration.Version,
				migration.Name,
				formatTimestamp(time.Now()),
			); err != nil {
				return fmt.Errorf("record migration %d %s: %w", migration.Version, migration.Name, err)
			}
		}

		return nil
	})
}

func ensureSchemaMigrationsTable(ctx context.Context, tx *sql.Tx) error {
	_, err := tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version INTEGER PRIMARY KEY,
		name TEXT NOT NULL CHECK (length(name) > 0),
		applied_at TEXT NOT NULL CHECK (length(applied_at) > 0)
	)`)
	if err != nil {
		return fmt.Errorf("create schema_migrations table: %w", err)
	}

	return nil
}

func appliedMigrationVersions(ctx context.Context, tx *sql.Tx) (map[int]bool, error) {
	rows, err := tx.QueryContext(ctx, `SELECT version FROM schema_migrations`)
	if err != nil {
		return nil, fmt.Errorf("query applied migrations: %w", err)
	}
	defer rows.Close()

	applied := make(map[int]bool)
	for rows.Next() {
		var version int
		if err := rows.Scan(&version); err != nil {
			return nil, fmt.Errorf("scan applied migration: %w", err)
		}

		applied[version] = true
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate applied migrations: %w", err)
	}

	return applied, nil
}
