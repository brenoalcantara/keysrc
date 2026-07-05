package service

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"keysrc/internal/security"
	"keysrc/internal/storage"
)

func TestCredentialServiceCRUD(t *testing.T) {
	ctx := context.Background()
	db := openMigratedTestDB(t, ctx)
	defer closeTestDB(t, db)

	session := testVaultSession(t)
	now := time.Date(2026, 6, 23, 12, 0, 0, 0, time.UTC)
	credentialService := NewCredentialServiceWithOptions(db, CredentialServiceOptions{
		Now: func() time.Time {
			return now
		},
	})

	created, err := credentialService.Create(ctx, session, CredentialInput{
		Title:    "GitHub",
		Username: "user@example.com",
		Password: "secret-password",
		URL:      "https://github.com",
		Notes:    "personal account",
		Tags:     []string{"dev", "dev", " personal "},
	})
	if err != nil {
		t.Fatalf("create credential: %v", err)
	}

	if created.ID == "" {
		t.Fatal("created credential id is empty")
	}

	if created.Title != "GitHub" || created.Username != "user@example.com" || created.Password != "secret-password" {
		t.Fatalf("created credential mismatch: %+v", created)
	}

	if len(created.Tags) != 2 || created.Tags[0] != "dev" || created.Tags[1] != "personal" {
		t.Fatalf("normalized tags = %#v, want [dev personal]", created.Tags)
	}

	assertSQLiteDoesNotContain(t, db, "GitHub")
	assertSQLiteDoesNotContain(t, db, "user@example.com")
	assertSQLiteDoesNotContain(t, db, "secret-password")

	listed, err := credentialService.List(ctx, session)
	if err != nil {
		t.Fatalf("list credentials: %v", err)
	}

	if len(listed) != 1 {
		t.Fatalf("listed credential count = %d, want 1", len(listed))
	}

	assertCredentialEqual(t, listed[0], created)

	loaded, err := credentialService.Get(ctx, session, created.ID)
	if err != nil {
		t.Fatalf("get credential: %v", err)
	}

	assertCredentialEqual(t, loaded, created)

	now = now.Add(time.Minute)
	updated, err := credentialService.Update(ctx, session, created.ID, CredentialInput{
		Title:    "GitHub Updated",
		Username: "updated@example.com",
		Password: "new-secret-password",
		URL:      "https://github.com/settings",
		Notes:    "updated note",
		Tags:     []string{"dev", "work"},
	})
	if err != nil {
		t.Fatalf("update credential: %v", err)
	}

	if updated.Title != "GitHub Updated" || updated.Password != "new-secret-password" {
		t.Fatalf("updated credential mismatch: %+v", updated)
	}

	if !updated.CreatedAt.Equal(created.CreatedAt) {
		t.Fatalf("updated created_at = %v, want %v", updated.CreatedAt, created.CreatedAt)
	}

	if !updated.UpdatedAt.After(created.UpdatedAt) {
		t.Fatalf("updated_at = %v, want after %v", updated.UpdatedAt, created.UpdatedAt)
	}

	assertSQLiteDoesNotContain(t, db, "GitHub Updated")
	assertSQLiteDoesNotContain(t, db, "new-secret-password")

	now = now.Add(time.Minute)
	if err := credentialService.Delete(ctx, session, created.ID); err != nil {
		t.Fatalf("delete credential: %v", err)
	}

	listed, err = credentialService.List(ctx, session)
	if err != nil {
		t.Fatalf("list credentials after delete: %v", err)
	}

	if len(listed) != 0 {
		t.Fatalf("listed credential count after delete = %d, want 0", len(listed))
	}
}

func TestCredentialServiceRejectsInvalidInput(t *testing.T) {
	ctx := context.Background()
	db := openMigratedTestDB(t, ctx)
	defer closeTestDB(t, db)

	session := testVaultSession(t)
	credentialService := NewCredentialService(db)

	_, err := credentialService.Create(ctx, session, CredentialInput{
		Password: "secret",
	})
	if !errors.Is(err, storage.ErrInvalidRecord) {
		t.Fatalf("missing title error = %v, want ErrInvalidRecord", err)
	}

	_, err = credentialService.Create(ctx, session, CredentialInput{
		Title: "No password",
	})
	if !errors.Is(err, storage.ErrInvalidRecord) {
		t.Fatalf("missing password error = %v, want ErrInvalidRecord", err)
	}

	lockedSession := &VaultSession{}
	_, err = credentialService.List(ctx, lockedSession)
	if err == nil || !strings.Contains(err.Error(), "vault is locked") {
		t.Fatalf("locked vault error = %v, want vault is locked", err)
	}

	err = credentialService.Delete(ctx, lockedSession, "any-id")
	if err == nil || !strings.Contains(err.Error(), "vault is locked") {
		t.Fatalf("locked delete error = %v, want vault is locked", err)
	}
}

func TestCredentialServiceRejectsWrongVaultKey(t *testing.T) {
	ctx := context.Background()
	db := openMigratedTestDB(t, ctx)
	defer closeTestDB(t, db)

	session := testVaultSession(t)
	credentialService := NewCredentialService(db)

	created, err := credentialService.Create(ctx, session, CredentialInput{
		Title:    "Bank",
		Username: "user",
		Password: "bank-secret",
	})
	if err != nil {
		t.Fatalf("create credential: %v", err)
	}

	wrongSession := testVaultSession(t)
	_, err = credentialService.Get(ctx, wrongSession, created.ID)
	if !errors.Is(err, security.ErrAuthenticationFailed) {
		t.Fatalf("wrong vault key error = %v, want ErrAuthenticationFailed", err)
	}
}

func TestCredentialServiceRejectsTamperedEncryptedRecord(t *testing.T) {
	testCases := []struct {
		name   string
		tamper func(*testing.T, *sql.DB, string)
	}{
		{
			name: "ciphertext",
			tamper: func(t *testing.T, db *sql.DB, id string) {
				t.Helper()
				var ciphertext []byte
				if err := db.QueryRow(`SELECT ciphertext FROM credentials WHERE id = ?`, id).Scan(&ciphertext); err != nil {
					t.Fatalf("load ciphertext: %v", err)
				}
				ciphertext[0] ^= 0x01
				if _, err := db.Exec(`UPDATE credentials SET ciphertext = ? WHERE id = ?`, ciphertext, id); err != nil {
					t.Fatalf("tamper ciphertext: %v", err)
				}
			},
		},
		{
			name: "nonce",
			tamper: func(t *testing.T, db *sql.DB, id string) {
				t.Helper()
				var nonce []byte
				if err := db.QueryRow(`SELECT nonce FROM credentials WHERE id = ?`, id).Scan(&nonce); err != nil {
					t.Fatalf("load nonce: %v", err)
				}
				nonce[0] ^= 0x01
				if _, err := db.Exec(`UPDATE credentials SET nonce = ? WHERE id = ?`, nonce, id); err != nil {
					t.Fatalf("tamper nonce: %v", err)
				}
			},
		},
		{
			name: "aad_version",
			tamper: func(t *testing.T, db *sql.DB, id string) {
				t.Helper()
				if _, err := db.Exec(`UPDATE credentials SET aad_version = aad_version + 1 WHERE id = ?`, id); err != nil {
					t.Fatalf("tamper aad version: %v", err)
				}
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			ctx := context.Background()
			db := openMigratedTestDB(t, ctx)
			defer closeTestDB(t, db)

			session := testVaultSession(t)
			credentialService := NewCredentialService(db)

			created, err := credentialService.Create(ctx, session, CredentialInput{
				Title:    "Tamper target",
				Username: "user",
				Password: "tamper-secret",
			})
			if err != nil {
				t.Fatalf("create credential: %v", err)
			}

			testCase.tamper(t, db, created.ID)

			_, err = credentialService.Get(ctx, session, created.ID)
			if !errors.Is(err, security.ErrAuthenticationFailed) {
				t.Fatalf("tampered record error = %v, want ErrAuthenticationFailed", err)
			}
		})
	}
}

func TestCredentialServiceConcurrentCreates(t *testing.T) {
	ctx := context.Background()
	db := openMigratedTestDB(t, ctx)
	defer closeTestDB(t, db)

	session := testVaultSession(t)
	credentialService := NewCredentialService(db)

	const total = 8
	var wg sync.WaitGroup
	errorsCh := make(chan error, total)

	for i := range total {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()

			_, err := credentialService.Create(ctx, session, CredentialInput{
				Title:    "Credential " + string(rune('A'+index)),
				Username: "user",
				Password: "secret",
			})
			errorsCh <- err
		}(i)
	}

	wg.Wait()
	close(errorsCh)

	for err := range errorsCh {
		if err != nil {
			t.Fatalf("concurrent create failed: %v", err)
		}
	}

	credentials, err := credentialService.List(ctx, session)
	if err != nil {
		t.Fatalf("list after concurrent creates: %v", err)
	}

	if len(credentials) != total {
		t.Fatalf("credential count after concurrent creates = %d, want %d", len(credentials), total)
	}
}

func TestCredentialServiceGeneratePassword(t *testing.T) {
	credentialService := NewCredentialService(nil)

	password, err := credentialService.GeneratePassword(security.PasswordGeneratorOptions{
		Length:         24,
		IncludeLower:   true,
		IncludeUpper:   true,
		IncludeDigits:  true,
		IncludeSymbols: true,
	})
	if err != nil {
		t.Fatalf("generate password: %v", err)
	}

	if len(password) != 24 {
		t.Fatalf("generated password length = %d, want 24", len(password))
	}
}

func testVaultSession(t *testing.T) *VaultSession {
	t.Helper()

	vaultKey, err := security.GenerateVaultKey()
	if err != nil {
		t.Fatalf("generate test vault key: %v", err)
	}

	t.Cleanup(func() {
		security.ZeroBytes(vaultKey)
	})

	return &VaultSession{
		VaultKey:   vaultKey,
		UnlockedAt: time.Now().UTC(),
	}
}

func assertCredentialEqual(t *testing.T, got Credential, want Credential) {
	t.Helper()

	if got.ID != want.ID ||
		got.Title != want.Title ||
		got.Username != want.Username ||
		got.Password != want.Password ||
		got.URL != want.URL ||
		got.Notes != want.Notes ||
		!got.CreatedAt.Equal(want.CreatedAt) ||
		!got.UpdatedAt.Equal(want.UpdatedAt) ||
		!stringSlicesEqual(got.Tags, want.Tags) {
		t.Fatalf("credential mismatch\ngot:  %+v\nwant: %+v", got, want)
	}
}

func stringSlicesEqual(left []string, right []string) bool {
	if len(left) != len(right) {
		return false
	}

	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}

	return true
}

func assertSQLiteDoesNotContain(t *testing.T, db *sql.DB, value string) {
	t.Helper()

	rows, err := db.Query(`SELECT ciphertext, nonce FROM credentials`)
	if err != nil {
		t.Fatalf("query raw credentials: %v", err)
	}
	defer func() {
		if err := rows.Close(); err != nil {
			t.Fatalf("close raw credentials rows: %v", err)
		}
	}()

	for rows.Next() {
		var ciphertext []byte
		var nonce []byte
		if err := rows.Scan(&ciphertext, &nonce); err != nil {
			t.Fatalf("scan raw credential: %v", err)
		}

		if bytes.Contains(ciphertext, []byte(value)) || bytes.Contains(nonce, []byte(value)) {
			t.Fatalf("sqlite encrypted fields contain plaintext value %q", value)
		}
	}

	if err := rows.Err(); err != nil {
		t.Fatalf("iterate raw credentials: %v", err)
	}
}
