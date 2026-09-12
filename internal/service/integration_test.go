package service

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"keysrc/internal/security"
	"keysrc/internal/storage"
)

func TestIntegrationVaultCredentialLifecycle(t *testing.T) {
	ctx := context.Background()
	db := openMigratedTestDB(t, ctx)
	defer closeTestDB(t, db)

	now := time.Date(2026, 7, 1, 9, 0, 0, 0, time.UTC)
	authService := NewAuthServiceWithOptions(db, AuthOptions{
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

	exists, err := authService.HasVault(ctx)
	if err != nil {
		t.Fatalf("check vault before first access: %v", err)
	}

	if exists {
		t.Fatal("vault exists before first access")
	}

	oldPassword := []byte("Very-Strong-Passphrase-2026!")
	newPassword := []byte("Even-Stronger-Passphrase-2027!")

	createdSession, err := authService.CreateVault(ctx, oldPassword)
	if err != nil {
		t.Fatalf("create vault from first access: %v", err)
	}
	defer createdSession.Lock()

	exists, err = authService.HasVault(ctx)
	if err != nil {
		t.Fatalf("check vault after first access: %v", err)
	}

	if !exists {
		t.Fatal("vault does not exist after first access")
	}

	_, err = authService.UnlockVault(ctx, []byte("Wrong-Strong-Passphrase-2026!"))
	if !errors.Is(err, security.ErrAuthenticationFailed) {
		t.Fatalf("wrong login error = %v, want ErrAuthenticationFailed", err)
	}

	session, err := authService.UnlockVault(ctx, oldPassword)
	if err != nil {
		t.Fatalf("login with correct password: %v", err)
	}
	defer session.Lock()

	if !bytes.Equal(session.VaultKey, createdSession.VaultKey) {
		t.Fatal("unlocked vault key differs from first access vault key")
	}

	persistentCredential, err := credentialService.Create(ctx, session, CredentialInput{
		Title:    "Email",
		Username: "user@example.com",
		Password: "email-secret",
		URL:      "https://mail.example.com",
		Notes:    "personal account",
		Tags:     []string{"personal", "mail"},
	})
	if err != nil {
		t.Fatalf("create persistent credential: %v", err)
	}

	temporaryCredential, err := credentialService.Create(ctx, session, CredentialInput{
		Title:    "GitHub",
		Username: "dev@example.com",
		Password: "github-secret",
		URL:      "https://github.com",
		Notes:    "developer account",
		Tags:     []string{"dev"},
	})
	if err != nil {
		t.Fatalf("create temporary credential: %v", err)
	}

	listed, err := credentialService.List(ctx, session)
	if err != nil {
		t.Fatalf("list credentials after create: %v", err)
	}

	assertCredentialEqual(t, credentialByID(t, listed, persistentCredential.ID), persistentCredential)
	assertCredentialEqual(t, credentialByID(t, listed, temporaryCredential.ID), temporaryCredential)

	now = now.Add(time.Minute)
	updatedTemporaryCredential, err := credentialService.Update(ctx, session, temporaryCredential.ID, CredentialInput{
		Title:    "GitHub Work",
		Username: "work@example.com",
		Password: "updated-github-secret",
		URL:      "https://github.com/settings/profile",
		Notes:    "updated developer account",
		Tags:     []string{"dev", "work"},
	})
	if err != nil {
		t.Fatalf("edit credential: %v", err)
	}

	loadedUpdatedCredential, err := credentialService.Get(ctx, session, temporaryCredential.ID)
	if err != nil {
		t.Fatalf("load edited credential: %v", err)
	}

	assertCredentialEqual(t, loadedUpdatedCredential, updatedTemporaryCredential)

	now = now.Add(time.Minute)
	if err := credentialService.Delete(ctx, session, temporaryCredential.ID); err != nil {
		t.Fatalf("delete credential: %v", err)
	}

	listed, err = credentialService.List(ctx, session)
	if err != nil {
		t.Fatalf("list credentials after delete: %v", err)
	}

	if credentialExists(listed, temporaryCredential.ID) {
		t.Fatal("deleted credential still appears in active list")
	}

	assertCredentialEqual(t, credentialByID(t, listed, persistentCredential.ID), persistentCredential)

	_, err = credentialService.Get(ctx, session, temporaryCredential.ID)
	if !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("get deleted credential error = %v, want ErrNotFound", err)
	}

	now = now.Add(time.Minute)
	changedSession, err := authService.ChangeMasterPassword(ctx, oldPassword, newPassword)
	if err != nil {
		t.Fatalf("change master password: %v", err)
	}
	defer changedSession.Lock()

	if !bytes.Equal(changedSession.VaultKey, session.VaultKey) {
		t.Fatal("changed password returned different vault key")
	}

	_, err = authService.UnlockVault(ctx, oldPassword)
	if !errors.Is(err, security.ErrAuthenticationFailed) {
		t.Fatalf("old password after change error = %v, want ErrAuthenticationFailed", err)
	}

	newSession, err := authService.UnlockVault(ctx, newPassword)
	if err != nil {
		t.Fatalf("login with new password: %v", err)
	}
	defer newSession.Lock()

	preservedCredential, err := credentialService.Get(ctx, newSession, persistentCredential.ID)
	if err != nil {
		t.Fatalf("load credential after password change: %v", err)
	}

	assertCredentialEqual(t, preservedCredential, persistentCredential)
}

func TestSecuritySQLiteFilesDoNotContainPlaintextSecrets(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "keysrc.sqlite3")
	db, err := storage.Open(ctx, dbPath)
	if err != nil {
		t.Fatalf("open test database: %v", err)
	}
	defer closeTestDB(t, db)

	if err := storage.Migrate(ctx, db); err != nil {
		t.Fatalf("migrate test database: %v", err)
	}

	now := time.Date(2026, 7, 1, 10, 0, 0, 0, time.UTC)
	authService := NewAuthServiceWithOptions(db, AuthOptions{
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

	session, err := authService.CreateVault(ctx, []byte("Very-Strong-Passphrase-2026!"))
	if err != nil {
		t.Fatalf("create vault: %v", err)
	}
	defer session.Lock()

	secrets := []string{
		"Sentinel Banking",
		"sentinel.user@example.com",
		"sentinel-password-2026!",
		"https://bank.example.com/login",
		"sentinel recovery note",
		"finance",
	}

	if _, err := credentialService.Create(ctx, session, CredentialInput{
		Title:    secrets[0],
		Username: secrets[1],
		Password: secrets[2],
		URL:      secrets[3],
		Notes:    secrets[4],
		Tags:     []string{secrets[5]},
	}); err != nil {
		t.Fatalf("create credential: %v", err)
	}

	if _, err := db.ExecContext(ctx, `PRAGMA wal_checkpoint(FULL)`); err != nil {
		t.Fatalf("checkpoint sqlite wal: %v", err)
	}

	assertDatabaseFilesDoNotContain(t, dbPath, secrets...)
}

func TestSecurityTamperedVaultMetadataFailsClosed(t *testing.T) {
	testCases := []struct {
		name          string
		tamper        func(*storage.VaultMetadata)
		wantAuthError bool
	}{
		{
			name: "verifier",
			tamper: func(metadata *storage.VaultMetadata) {
				metadata.Verifier[0] ^= 0x01
			},
			wantAuthError: true,
		},
		{
			name: "encrypted vault key",
			tamper: func(metadata *storage.VaultMetadata) {
				metadata.EncryptedVaultKey[0] ^= 0x01
			},
			wantAuthError: true,
		},
		{
			name: "vault key nonce",
			tamper: func(metadata *storage.VaultMetadata) {
				metadata.VaultKeyNonce[0] ^= 0x01
			},
			wantAuthError: true,
		},
		{
			name: "kdf salt",
			tamper: func(metadata *storage.VaultMetadata) {
				metadata.KDFSalt[0] ^= 0x01
			},
			wantAuthError: true,
		},
		{
			name: "unsupported crypto version",
			tamper: func(metadata *storage.VaultMetadata) {
				metadata.CryptoVersion++
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			ctx := context.Background()
			db := openMigratedTestDB(t, ctx)
			defer closeTestDB(t, db)

			now := time.Date(2026, 7, 1, 11, 0, 0, 0, time.UTC)
			authService := NewAuthServiceWithOptions(db, AuthOptions{
				KDFParams: testKDFParams(),
				Now: func() time.Time {
					return now
				},
			})

			masterPassword := []byte("Very-Strong-Passphrase-2026!")
			session, err := authService.CreateVault(ctx, masterPassword)
			if err != nil {
				t.Fatalf("create vault: %v", err)
			}
			session.Lock()

			repo := storage.NewVaultRepository(db)
			metadata, err := repo.Get(ctx)
			if err != nil {
				t.Fatalf("load vault metadata: %v", err)
			}

			testCase.tamper(&metadata)
			metadata.UpdatedAt = metadata.UpdatedAt.Add(time.Second)
			if err := repo.Update(ctx, metadata); err != nil {
				t.Fatalf("persist tampered metadata: %v", err)
			}

			unlocked, err := authService.UnlockVault(ctx, masterPassword)
			if unlocked != nil {
				unlocked.Lock()
			}

			if err == nil {
				t.Fatal("tampered vault metadata unlocked successfully")
			}

			if testCase.wantAuthError && !errors.Is(err, security.ErrAuthenticationFailed) {
				t.Fatalf("tampered metadata error = %v, want ErrAuthenticationFailed", err)
			}
		})
	}
}

func credentialByID(t *testing.T, credentials []Credential, id string) Credential {
	t.Helper()

	for _, credential := range credentials {
		if credential.ID == id {
			return credential
		}
	}

	t.Fatalf("credential %q not found in list", id)
	return Credential{}
}

func credentialExists(credentials []Credential, id string) bool {
	for _, credential := range credentials {
		if credential.ID == id {
			return true
		}
	}

	return false
}

func assertDatabaseFilesDoNotContain(t *testing.T, databasePath string, values ...string) {
	t.Helper()

	for _, path := range []string{databasePath, databasePath + "-wal", databasePath + "-shm"} {
		content, err := os.ReadFile(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}

		if err != nil {
			t.Fatalf("read database file %s: %v", path, err)
		}

		for _, value := range values {
			if bytes.Contains(content, []byte(value)) {
				t.Fatalf("database file %s contains plaintext value %q", path, value)
			}
		}
	}
}
