package storage

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestMigrateCreatesVersionedSchema(t *testing.T) {
	ctx := context.Background()
	db := openMigratedTestDB(t, ctx)
	defer closeTestDB(t, db)

	assertTableExists(t, db, "schema_migrations")
	assertTableExists(t, db, "vault_metadata")
	assertTableExists(t, db, "credentials")
	assertTableExists(t, db, "security_events")

	var migrationCount int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM schema_migrations`).Scan(&migrationCount); err != nil {
		t.Fatalf("count migrations: %v", err)
	}

	if migrationCount != len(migrations) {
		t.Fatalf("migration count = %d, want %d", migrationCount, len(migrations))
	}

	if err := Migrate(ctx, db); err != nil {
		t.Fatalf("run migrations twice: %v", err)
	}

	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM schema_migrations`).Scan(&migrationCount); err != nil {
		t.Fatalf("count migrations after second run: %v", err)
	}

	if migrationCount != len(migrations) {
		t.Fatalf("migration count after second run = %d, want %d", migrationCount, len(migrations))
	}

	var userVersion int
	if err := db.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&userVersion); err != nil {
		t.Fatalf("query user_version: %v", err)
	}

	if userVersion != CurrentSchemaVersion {
		t.Fatalf("user_version = %d, want %d", userVersion, CurrentSchemaVersion)
	}
}

func TestVaultRepositoryCreateLoadUpdateAndRollback(t *testing.T) {
	ctx := context.Background()
	db := openMigratedTestDB(t, ctx)
	defer closeTestDB(t, db)

	repo := NewVaultRepository(db)

	exists, err := repo.Exists(ctx)
	if err != nil {
		t.Fatalf("check initial existence: %v", err)
	}

	if exists {
		t.Fatal("vault metadata exists before creation")
	}

	now := time.Date(2026, 6, 18, 12, 0, 0, 0, time.UTC)
	metadata := sampleVaultMetadata(now)

	if err := WithinTx(ctx, db, func(tx *sql.Tx) error {
		return NewVaultRepository(tx).Create(ctx, metadata)
	}); err != nil {
		t.Fatalf("create metadata in transaction: %v", err)
	}

	exists, err = repo.Exists(ctx)
	if err != nil {
		t.Fatalf("check existence after create: %v", err)
	}

	if !exists {
		t.Fatal("vault metadata does not exist after creation")
	}

	loaded, err := repo.Get(ctx)
	if err != nil {
		t.Fatalf("load metadata: %v", err)
	}

	assertVaultMetadataEqual(t, loaded, metadata)

	updated := loaded
	updated.KDFSalt = []byte("new-salt")
	updated.Verifier = []byte("new-verifier")
	updated.UpdatedAt = now.Add(time.Minute)

	if err := repo.Update(ctx, updated); err != nil {
		t.Fatalf("update metadata: %v", err)
	}

	loaded, err = repo.Get(ctx)
	if err != nil {
		t.Fatalf("load updated metadata: %v", err)
	}

	assertVaultMetadataEqual(t, loaded, updated)

	rolledBack := updated
	rolledBack.Verifier = []byte("rolled-back")
	rolledBack.UpdatedAt = now.Add(2 * time.Minute)
	expectedErr := errors.New("force rollback")

	err = WithinTx(ctx, db, func(tx *sql.Tx) error {
		if err := NewVaultRepository(tx).Update(ctx, rolledBack); err != nil {
			return err
		}

		return expectedErr
	})
	if !errors.Is(err, expectedErr) {
		t.Fatalf("rollback error = %v, want %v", err, expectedErr)
	}

	loaded, err = repo.Get(ctx)
	if err != nil {
		t.Fatalf("load metadata after rollback: %v", err)
	}

	assertVaultMetadataEqual(t, loaded, updated)
}

func TestCredentialRepositoryCRUDAndRollback(t *testing.T) {
	ctx := context.Background()
	db := openMigratedTestDB(t, ctx)
	defer closeTestDB(t, db)

	repo := NewCredentialRepository(db)
	now := time.Date(2026, 6, 18, 12, 0, 0, 0, time.UTC)
	first := CredentialRecord{
		ID:         "cred-1",
		Ciphertext: []byte("ciphertext-1"),
		Nonce:      []byte("nonce-1"),
		AADVersion: 1,
		CreatedAt:  now,
		UpdatedAt:  now,
	}
	second := CredentialRecord{
		ID:         "cred-2",
		Ciphertext: []byte("ciphertext-2"),
		Nonce:      []byte("nonce-2"),
		AADVersion: 1,
		CreatedAt:  now,
		UpdatedAt:  now.Add(time.Minute),
	}

	if err := repo.Create(ctx, first); err != nil {
		t.Fatalf("create first credential: %v", err)
	}

	if err := repo.Create(ctx, second); err != nil {
		t.Fatalf("create second credential: %v", err)
	}

	active, err := repo.ListActive(ctx)
	if err != nil {
		t.Fatalf("list active credentials: %v", err)
	}

	if len(active) != 2 {
		t.Fatalf("active credential count = %d, want 2", len(active))
	}

	if active[0].ID != second.ID || active[1].ID != first.ID {
		t.Fatalf("active credential order = [%s, %s], want [%s, %s]", active[0].ID, active[1].ID, second.ID, first.ID)
	}

	loaded, err := repo.Get(ctx, first.ID)
	if err != nil {
		t.Fatalf("get first credential: %v", err)
	}

	assertCredentialEqual(t, loaded, first)

	first.Ciphertext = []byte("updated-ciphertext")
	first.Nonce = []byte("updated-nonce")
	first.UpdatedAt = now.Add(2 * time.Minute)

	if err := repo.Update(ctx, first); err != nil {
		t.Fatalf("update first credential: %v", err)
	}

	loaded, err = repo.Get(ctx, first.ID)
	if err != nil {
		t.Fatalf("get updated first credential: %v", err)
	}

	assertCredentialEqual(t, loaded, first)

	deletedAt := now.Add(3 * time.Minute)
	if err := repo.SoftDelete(ctx, second.ID, deletedAt); err != nil {
		t.Fatalf("soft delete second credential: %v", err)
	}

	active, err = repo.ListActive(ctx)
	if err != nil {
		t.Fatalf("list active credentials after delete: %v", err)
	}

	if len(active) != 1 || active[0].ID != first.ID {
		t.Fatalf("active credentials after delete = %+v, want only %s", active, first.ID)
	}

	rolledBack := CredentialRecord{
		ID:         "cred-rollback",
		Ciphertext: []byte("ciphertext-rollback"),
		Nonce:      []byte("nonce-rollback"),
		AADVersion: 1,
		CreatedAt:  now,
		UpdatedAt:  now,
	}
	expectedErr := errors.New("force rollback")

	err = WithinTx(ctx, db, func(tx *sql.Tx) error {
		if err := NewCredentialRepository(tx).Create(ctx, rolledBack); err != nil {
			return err
		}

		return expectedErr
	})
	if !errors.Is(err, expectedErr) {
		t.Fatalf("rollback error = %v, want %v", err, expectedErr)
	}

	_, err = repo.Get(ctx, rolledBack.ID)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("get rolled back credential error = %v, want ErrNotFound", err)
	}
}

func TestOpenAndSecureDatabaseFilesApplyRestrictivePermissions(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "keysrc.sqlite3")

	db, err := Open(ctx, dbPath)
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	defer closeTestDB(t, db)

	if err := Migrate(ctx, db); err != nil {
		t.Fatalf("migrate database: %v", err)
	}

	walPath := dbPath + "-wal"
	shmPath := dbPath + "-shm"
	if err := os.WriteFile(walPath, []byte("wal"), 0o666); err != nil {
		t.Fatalf("write wal sidecar: %v", err)
	}

	if err := os.WriteFile(shmPath, []byte("shm"), 0o666); err != nil {
		t.Fatalf("write shm sidecar: %v", err)
	}

	if err := SecureDatabaseFiles(dbPath); err != nil {
		t.Fatalf("secure database files: %v", err)
	}

	assertFileMode(t, dbPath, secureFileMode)
	assertFileMode(t, walPath, secureFileMode)
	assertFileMode(t, shmPath, secureFileMode)
}

func TestMigrateRejectsCorruptedDatabaseFile(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "keysrc.sqlite3")
	if err := os.WriteFile(dbPath, []byte("not a sqlite database"), 0o600); err != nil {
		t.Fatalf("write corrupted database: %v", err)
	}

	db, err := Open(ctx, dbPath)
	if err == nil {
		defer closeTestDB(t, db)
		err = Migrate(ctx, db)
	}

	if err == nil {
		t.Fatal("opening or migrating corrupted database succeeded")
	}
}

func openMigratedTestDB(t *testing.T, ctx context.Context) *sql.DB {
	t.Helper()

	dbPath := filepath.Join(t.TempDir(), "keysrc.sqlite3")
	db, err := Open(ctx, dbPath)
	if err != nil {
		t.Fatalf("open test database: %v", err)
	}

	if err := Migrate(ctx, db); err != nil {
		if closeErr := db.Close(); closeErr != nil {
			t.Fatalf("migrate test database: %v; close test database: %v", err, closeErr)
		}
		t.Fatalf("migrate test database: %v", err)
	}

	return db
}

func sampleVaultMetadata(now time.Time) VaultMetadata {
	return VaultMetadata{
		SchemaVersion:     CurrentSchemaVersion,
		CryptoVersion:     1,
		KDFName:           "argon2id",
		KDFMemoryKiB:      65536,
		KDFIterations:     3,
		KDFParallelism:    2,
		KDFSalt:           []byte("salt"),
		Verifier:          []byte("verifier"),
		EncryptedVaultKey: []byte("encrypted-vault-key"),
		VaultKeyNonce:     []byte("vault-key-nonce"),
		CreatedAt:         now,
		UpdatedAt:         now,
	}
}

func assertTableExists(t *testing.T, db *sql.DB, tableName string) {
	t.Helper()

	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?`, tableName).Scan(&count); err != nil {
		t.Fatalf("query sqlite_master for table %s: %v", tableName, err)
	}

	if count != 1 {
		t.Fatalf("table %s count = %d, want 1", tableName, count)
	}
}

func closeTestDB(t *testing.T, db *sql.DB) {
	t.Helper()

	if err := db.Close(); err != nil {
		t.Fatalf("close test database: %v", err)
	}
}

func assertFileMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}

	got := info.Mode().Perm()
	if got != want {
		t.Fatalf("mode for %s = %o, want %o", path, got, want)
	}
}

func assertVaultMetadataEqual(t *testing.T, got VaultMetadata, want VaultMetadata) {
	t.Helper()

	if got.SchemaVersion != want.SchemaVersion ||
		got.CryptoVersion != want.CryptoVersion ||
		got.KDFName != want.KDFName ||
		got.KDFMemoryKiB != want.KDFMemoryKiB ||
		got.KDFIterations != want.KDFIterations ||
		got.KDFParallelism != want.KDFParallelism ||
		!got.CreatedAt.Equal(want.CreatedAt) ||
		!got.UpdatedAt.Equal(want.UpdatedAt) ||
		string(got.KDFSalt) != string(want.KDFSalt) ||
		string(got.Verifier) != string(want.Verifier) ||
		string(got.EncryptedVaultKey) != string(want.EncryptedVaultKey) ||
		string(got.VaultKeyNonce) != string(want.VaultKeyNonce) {
		t.Fatalf("metadata mismatch\ngot:  %+v\nwant: %+v", got, want)
	}
}

func assertCredentialEqual(t *testing.T, got CredentialRecord, want CredentialRecord) {
	t.Helper()

	if got.ID != want.ID ||
		got.AADVersion != want.AADVersion ||
		!got.CreatedAt.Equal(want.CreatedAt) ||
		!got.UpdatedAt.Equal(want.UpdatedAt) ||
		string(got.Ciphertext) != string(want.Ciphertext) ||
		string(got.Nonce) != string(want.Nonce) {
		t.Fatalf("credential mismatch\ngot:  %+v\nwant: %+v", got, want)
	}

	switch {
	case got.DeletedAt == nil && want.DeletedAt == nil:
		return
	case got.DeletedAt == nil || want.DeletedAt == nil:
		t.Fatalf("credential deleted_at mismatch got %v want %v", got.DeletedAt, want.DeletedAt)
	case !got.DeletedAt.Equal(*want.DeletedAt):
		t.Fatalf("credential deleted_at mismatch got %v want %v", got.DeletedAt, want.DeletedAt)
	}
}
