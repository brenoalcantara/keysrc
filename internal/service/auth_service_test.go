package service

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"keysrc/internal/security"
	"keysrc/internal/storage"
)

func TestAuthServiceCreateAndUnlockVault(t *testing.T) {
	ctx := context.Background()
	db := openMigratedTestDB(t, ctx)
	defer closeTestDB(t, db)

	now := time.Date(2026, 6, 23, 10, 0, 0, 0, time.UTC)
	auth := NewAuthServiceWithOptions(db, AuthOptions{
		KDFParams: testKDFParams(),
		Now: func() time.Time {
			return now
		},
	})

	exists, err := auth.HasVault(ctx)
	if err != nil {
		t.Fatalf("check initial vault existence: %v", err)
	}

	if exists {
		t.Fatal("vault exists before first access")
	}

	password := []byte("Very-Strong-Passphrase-2026!")
	session, err := auth.CreateVault(ctx, password)
	if err != nil {
		t.Fatalf("create vault: %v", err)
	}
	defer session.Lock()

	if len(session.VaultKey) != security.KeySize {
		t.Fatalf("vault key length = %d, want %d", len(session.VaultKey), security.KeySize)
	}

	exists, err = auth.HasVault(ctx)
	if err != nil {
		t.Fatalf("check vault existence after create: %v", err)
	}

	if !exists {
		t.Fatal("vault does not exist after create")
	}

	metadata, err := storage.NewVaultRepository(db).Get(ctx)
	if err != nil {
		t.Fatalf("load persisted vault metadata: %v", err)
	}

	if metadata.KDFName != kdfNameArgon2id {
		t.Fatalf("kdf name = %q, want %q", metadata.KDFName, kdfNameArgon2id)
	}

	if metadata.CryptoVersion != security.CryptoVersion {
		t.Fatalf("crypto version = %d, want %d", metadata.CryptoVersion, security.CryptoVersion)
	}

	if bytes.Equal(metadata.EncryptedVaultKey, session.VaultKey) {
		t.Fatal("encrypted vault key matches plaintext vault key")
	}

	unlocked, err := auth.UnlockVault(ctx, []byte("Very-Strong-Passphrase-2026!"))
	if err != nil {
		t.Fatalf("unlock vault: %v", err)
	}
	defer unlocked.Lock()

	if !bytes.Equal(unlocked.VaultKey, session.VaultKey) {
		t.Fatal("unlocked vault key differs from created vault key")
	}

	_, err = auth.UnlockVault(ctx, []byte("Wrong-Strong-Passphrase-2026!"))
	if !errors.Is(err, security.ErrAuthenticationFailed) {
		t.Fatalf("wrong password error = %v, want ErrAuthenticationFailed", err)
	}

	_, err = auth.CreateVault(ctx, []byte("Another-Strong-Passphrase-2026!"))
	if !errors.Is(err, storage.ErrAlreadyExists) {
		t.Fatalf("duplicate create error = %v, want ErrAlreadyExists", err)
	}
}

func TestAuthServiceRejectsWeakPasswordBeforePersistingVault(t *testing.T) {
	ctx := context.Background()
	db := openMigratedTestDB(t, ctx)
	defer closeTestDB(t, db)

	auth := NewAuthServiceWithOptions(db, AuthOptions{
		KDFParams: testKDFParams(),
	})

	_, err := auth.CreateVault(ctx, []byte("weak"))
	if !errors.Is(err, security.ErrWeakPassword) {
		t.Fatalf("weak password error = %v, want ErrWeakPassword", err)
	}

	exists, err := auth.HasVault(ctx)
	if err != nil {
		t.Fatalf("check vault existence after weak password: %v", err)
	}

	if exists {
		t.Fatal("vault was persisted after weak password")
	}
}

func TestAuthServiceChangeMasterPassword(t *testing.T) {
	ctx := context.Background()
	db := openMigratedTestDB(t, ctx)
	defer closeTestDB(t, db)

	now := time.Date(2026, 6, 23, 10, 0, 0, 0, time.UTC)
	auth := NewAuthServiceWithOptions(db, AuthOptions{
		KDFParams: testKDFParams(),
		Now: func() time.Time {
			return now
		},
	})
	credentialService := NewCredentialServiceWithOptions(db, CredentialServiceOptions{
		Now: func() time.Time {
			return now
		},
	})

	oldPassword := []byte("Very-Strong-Passphrase-2026!")
	newPassword := []byte("Even-Stronger-Passphrase-2027!")

	session, err := auth.CreateVault(ctx, oldPassword)
	if err != nil {
		t.Fatalf("create vault: %v", err)
	}
	defer session.Lock()

	createdCredential, err := credentialService.Create(ctx, session, CredentialInput{
		Title:    "Email",
		Username: "user@example.com",
		Password: "email-secret",
		URL:      "https://mail.example.com",
	})
	if err != nil {
		t.Fatalf("create credential before password change: %v", err)
	}

	metadataBefore, err := storage.NewVaultRepository(db).Get(ctx)
	if err != nil {
		t.Fatalf("load metadata before change: %v", err)
	}

	_, err = auth.ChangeMasterPassword(ctx, []byte("Wrong-Strong-Passphrase-2026!"), newPassword)
	if !errors.Is(err, security.ErrAuthenticationFailed) {
		t.Fatalf("wrong current password error = %v, want ErrAuthenticationFailed", err)
	}

	_, err = auth.UnlockVault(ctx, oldPassword)
	if err != nil {
		t.Fatalf("old password should still work after failed change: %v", err)
	}

	_, err = auth.ChangeMasterPassword(ctx, oldPassword, []byte("weak"))
	if !errors.Is(err, security.ErrWeakPassword) {
		t.Fatalf("weak new password error = %v, want ErrWeakPassword", err)
	}

	now = now.Add(time.Minute)
	changedSession, err := auth.ChangeMasterPassword(ctx, oldPassword, newPassword)
	if err != nil {
		t.Fatalf("change master password: %v", err)
	}
	defer changedSession.Lock()

	if !bytes.Equal(changedSession.VaultKey, session.VaultKey) {
		t.Fatal("changed session vault key differs from original vault key")
	}

	metadataAfter, err := storage.NewVaultRepository(db).Get(ctx)
	if err != nil {
		t.Fatalf("load metadata after change: %v", err)
	}

	if !metadataAfter.CreatedAt.Equal(metadataBefore.CreatedAt) {
		t.Fatalf("created_at changed from %v to %v", metadataBefore.CreatedAt, metadataAfter.CreatedAt)
	}

	if !metadataAfter.UpdatedAt.After(metadataBefore.UpdatedAt) {
		t.Fatalf("updated_at = %v, want after %v", metadataAfter.UpdatedAt, metadataBefore.UpdatedAt)
	}

	if bytes.Equal(metadataAfter.KDFSalt, metadataBefore.KDFSalt) {
		t.Fatal("kdf salt did not change")
	}

	if bytes.Equal(metadataAfter.EncryptedVaultKey, metadataBefore.EncryptedVaultKey) {
		t.Fatal("encrypted vault key did not change")
	}

	_, err = auth.UnlockVault(ctx, oldPassword)
	if !errors.Is(err, security.ErrAuthenticationFailed) {
		t.Fatalf("old password after change error = %v, want ErrAuthenticationFailed", err)
	}

	unlockedWithNewPassword, err := auth.UnlockVault(ctx, newPassword)
	if err != nil {
		t.Fatalf("unlock with new password: %v", err)
	}
	defer unlockedWithNewPassword.Lock()

	if !bytes.Equal(unlockedWithNewPassword.VaultKey, session.VaultKey) {
		t.Fatal("new password unlocked a different vault key")
	}

	loadedCredential, err := credentialService.Get(ctx, unlockedWithNewPassword, createdCredential.ID)
	if err != nil {
		t.Fatalf("load credential after password change: %v", err)
	}

	if loadedCredential.Password != createdCredential.Password {
		t.Fatalf("credential password after change = %q, want %q", loadedCredential.Password, createdCredential.Password)
	}
}

func TestVaultSessionLockZeroesVaultKey(t *testing.T) {
	session := &VaultSession{
		VaultKey: []byte("12345678901234567890123456789012"),
	}
	key := session.VaultKey

	session.Lock()

	if session.VaultKey != nil {
		t.Fatal("session vault key was not cleared")
	}

	for i, value := range key {
		if value != 0 {
			t.Fatalf("vault key byte %d = %d, want 0", i, value)
		}
	}
}

func openMigratedTestDB(t *testing.T, ctx context.Context) *sql.DB {
	t.Helper()

	dbPath := filepath.Join(t.TempDir(), "keysrc.sqlite3")
	db, err := storage.Open(ctx, dbPath)
	if err != nil {
		t.Fatalf("open test database: %v", err)
	}

	if err := storage.Migrate(ctx, db); err != nil {
		if closeErr := db.Close(); closeErr != nil {
			t.Fatalf("migrate test database: %v; close test database: %v", err, closeErr)
		}
		t.Fatalf("migrate test database: %v", err)
	}

	return db
}

func closeTestDB(t *testing.T, db *sql.DB) {
	t.Helper()

	if err := db.Close(); err != nil {
		t.Fatalf("close test database: %v", err)
	}
}

func testKDFParams() security.KDFParams {
	return security.KDFParams{
		MemoryKiB:   security.MinimumKDFMemoryKiB,
		Iterations:  1,
		Parallelism: 1,
		SaltLength:  security.MinimumKDFSaltLength,
		KeyLength:   security.KeySize,
	}
}
