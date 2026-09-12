package security

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestDeriveMasterKeyAndSubkeys(t *testing.T) {
	params := testKDFParams()
	password := []byte("correct horse battery staple")
	salt := []byte("1234567890abcdef")

	key1, err := DeriveMasterKey(password, salt, params)
	if err != nil {
		t.Fatalf("derive first key: %v", err)
	}
	defer ZeroBytes(key1)

	key2, err := DeriveMasterKey(password, salt, params)
	if err != nil {
		t.Fatalf("derive second key: %v", err)
	}
	defer ZeroBytes(key2)

	if !bytes.Equal(key1, key2) {
		t.Fatal("same password and salt produced different master keys")
	}

	if len(key1) != KeySize {
		t.Fatalf("master key length = %d, want %d", len(key1), KeySize)
	}

	subkeys, err := DeriveSubkeys(key1)
	if err != nil {
		t.Fatalf("derive subkeys: %v", err)
	}
	defer subkeys.Zero()

	if len(subkeys.WrapKey) != KeySize || len(subkeys.AuthKey) != KeySize {
		t.Fatalf("subkey lengths = %d/%d, want %d/%d", len(subkeys.WrapKey), len(subkeys.AuthKey), KeySize, KeySize)
	}

	if bytes.Equal(subkeys.WrapKey, subkeys.AuthKey) {
		t.Fatal("wrap key and auth key must be distinct")
	}
}

func TestDeriveMasterKeyRejectsInvalidInputs(t *testing.T) {
	validParams := testKDFParams()
	validPassword := []byte("password")
	validSalt := []byte("1234567890abcdef")

	testCases := []struct {
		name     string
		password []byte
		salt     []byte
		params   KDFParams
	}{
		{
			name:     "empty password",
			password: nil,
			salt:     validSalt,
			params:   validParams,
		},
		{
			name:     "short salt",
			password: validPassword,
			salt:     []byte("short"),
			params:   validParams,
		},
		{
			name:     "memory below minimum",
			password: validPassword,
			salt:     validSalt,
			params: KDFParams{
				MemoryKiB:   MinimumKDFMemoryKiB - 1,
				Iterations:  validParams.Iterations,
				Parallelism: validParams.Parallelism,
				SaltLength:  validParams.SaltLength,
				KeyLength:   validParams.KeyLength,
			},
		},
		{
			name:     "zero iterations",
			password: validPassword,
			salt:     validSalt,
			params: KDFParams{
				MemoryKiB:   validParams.MemoryKiB,
				Iterations:  0,
				Parallelism: validParams.Parallelism,
				SaltLength:  validParams.SaltLength,
				KeyLength:   validParams.KeyLength,
			},
		},
		{
			name:     "zero parallelism",
			password: validPassword,
			salt:     validSalt,
			params: KDFParams{
				MemoryKiB:   validParams.MemoryKiB,
				Iterations:  validParams.Iterations,
				Parallelism: 0,
				SaltLength:  validParams.SaltLength,
				KeyLength:   validParams.KeyLength,
			},
		},
		{
			name:     "wrong key length",
			password: validPassword,
			salt:     validSalt,
			params: KDFParams{
				MemoryKiB:   validParams.MemoryKiB,
				Iterations:  validParams.Iterations,
				Parallelism: validParams.Parallelism,
				SaltLength:  validParams.SaltLength,
				KeyLength:   KeySize - 1,
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := DeriveMasterKey(testCase.password, testCase.salt, testCase.params); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("derive error = %v, want ErrInvalidInput", err)
			}
		})
	}

	creationParams := validParams
	creationParams.SaltLength = MinimumKDFSaltLength - 1
	if _, err := GenerateSalt(creationParams); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("short creation salt length error = %v, want ErrInvalidInput", err)
	}
}

func TestVerifierRejectsWrongPassword(t *testing.T) {
	params := testKDFParams()
	salt := []byte("1234567890abcdef")

	correctMasterKey, err := DeriveMasterKey([]byte("correct password"), salt, params)
	if err != nil {
		t.Fatalf("derive correct master key: %v", err)
	}
	defer ZeroBytes(correctMasterKey)

	correctSubkeys, err := DeriveSubkeys(correctMasterKey)
	if err != nil {
		t.Fatalf("derive correct subkeys: %v", err)
	}
	defer correctSubkeys.Zero()

	verifier, err := CreateVerifier(correctSubkeys.AuthKey)
	if err != nil {
		t.Fatalf("create verifier: %v", err)
	}
	defer ZeroBytes(verifier)

	wrongMasterKey, err := DeriveMasterKey([]byte("wrong password"), salt, params)
	if err != nil {
		t.Fatalf("derive wrong master key: %v", err)
	}
	defer ZeroBytes(wrongMasterKey)

	wrongSubkeys, err := DeriveSubkeys(wrongMasterKey)
	if err != nil {
		t.Fatalf("derive wrong subkeys: %v", err)
	}
	defer wrongSubkeys.Zero()

	if !VerifyVerifier(correctSubkeys.AuthKey, verifier) {
		t.Fatal("correct password verifier was rejected")
	}

	if VerifyVerifier(wrongSubkeys.AuthKey, verifier) {
		t.Fatal("wrong password verifier was accepted")
	}
}

func TestVaultEnvelopeOpensOnlyWithCorrectPassword(t *testing.T) {
	params := testKDFParams()
	password := []byte("correct horse battery staple")

	envelope, vaultKey, err := NewVaultEnvelope(password, params)
	if err != nil {
		t.Fatalf("create vault envelope: %v", err)
	}
	defer ZeroBytes(vaultKey)

	openedVaultKey, err := OpenVaultEnvelope(password, envelope)
	if err != nil {
		t.Fatalf("open vault envelope: %v", err)
	}
	defer ZeroBytes(openedVaultKey)

	if !bytes.Equal(openedVaultKey, vaultKey) {
		t.Fatal("opened vault key differs from created vault key")
	}

	if _, err := OpenVaultEnvelope([]byte("wrong password"), envelope); !errors.Is(err, ErrAuthenticationFailed) {
		t.Fatalf("wrong password error = %v, want ErrAuthenticationFailed", err)
	}

	tamperedVerifier := cloneEnvelope(envelope)
	tamperedVerifier.Verifier[0] ^= 0x01
	if _, err := OpenVaultEnvelope(password, tamperedVerifier); !errors.Is(err, ErrAuthenticationFailed) {
		t.Fatalf("tampered verifier error = %v, want ErrAuthenticationFailed", err)
	}

	tamperedCiphertext := cloneEnvelope(envelope)
	tamperedCiphertext.EncryptedVaultKey[0] ^= 0x01
	if _, err := OpenVaultEnvelope(password, tamperedCiphertext); !errors.Is(err, ErrAuthenticationFailed) {
		t.Fatalf("tampered vault key ciphertext error = %v, want ErrAuthenticationFailed", err)
	}

	tamperedNonce := cloneEnvelope(envelope)
	tamperedNonce.VaultKeyNonce[0] ^= 0x01
	if _, err := OpenVaultEnvelope(password, tamperedNonce); !errors.Is(err, ErrAuthenticationFailed) {
		t.Fatalf("tampered vault key nonce error = %v, want ErrAuthenticationFailed", err)
	}
}

func TestSealOpenRejectsWrongAADKeyAndTampering(t *testing.T) {
	key, err := RandomBytes(KeySize)
	if err != nil {
		t.Fatalf("random key: %v", err)
	}
	defer ZeroBytes(key)

	plaintext := []byte("secret payload")
	aad := []byte("aad-v1")

	blob, err := Seal(key, plaintext, aad)
	if err != nil {
		t.Fatalf("seal plaintext: %v", err)
	}

	opened, err := Open(key, blob, aad)
	if err != nil {
		t.Fatalf("open sealed plaintext: %v", err)
	}

	if !bytes.Equal(opened, plaintext) {
		t.Fatalf("opened plaintext = %q, want %q", opened, plaintext)
	}

	if _, err := Open(key, blob, []byte("aad-v2")); !errors.Is(err, ErrAuthenticationFailed) {
		t.Fatalf("wrong aad error = %v, want ErrAuthenticationFailed", err)
	}

	wrongKey, err := RandomBytes(KeySize)
	if err != nil {
		t.Fatalf("random wrong key: %v", err)
	}
	defer ZeroBytes(wrongKey)

	if _, err := Open(wrongKey, blob, aad); !errors.Is(err, ErrAuthenticationFailed) {
		t.Fatalf("wrong key error = %v, want ErrAuthenticationFailed", err)
	}

	tamperedCiphertext := EncryptedBlob{
		Ciphertext: cloneBytes(blob.Ciphertext),
		Nonce:      cloneBytes(blob.Nonce),
	}
	tamperedCiphertext.Ciphertext[0] ^= 0x01
	if _, err := Open(key, tamperedCiphertext, aad); !errors.Is(err, ErrAuthenticationFailed) {
		t.Fatalf("tampered ciphertext error = %v, want ErrAuthenticationFailed", err)
	}

	tamperedNonce := EncryptedBlob{
		Ciphertext: cloneBytes(blob.Ciphertext),
		Nonce:      cloneBytes(blob.Nonce),
	}
	tamperedNonce.Nonce[0] ^= 0x01
	if _, err := Open(key, tamperedNonce, aad); !errors.Is(err, ErrAuthenticationFailed) {
		t.Fatalf("tampered nonce error = %v, want ErrAuthenticationFailed", err)
	}
}

func TestCredentialEncryptionBindsCredentialID(t *testing.T) {
	vaultKey, err := GenerateVaultKey()
	if err != nil {
		t.Fatalf("generate vault key: %v", err)
	}
	defer ZeroBytes(vaultKey)

	plaintext := []byte(`{"title":"GitHub","username":"user","password":"secret"}`)
	blob, err := EncryptCredential(vaultKey, "cred-1", plaintext)
	if err != nil {
		t.Fatalf("encrypt credential: %v", err)
	}

	opened, err := DecryptCredential(vaultKey, "cred-1", blob)
	if err != nil {
		t.Fatalf("decrypt credential: %v", err)
	}

	if !bytes.Equal(opened, plaintext) {
		t.Fatal("decrypted credential differs from original plaintext")
	}

	if _, err := DecryptCredential(vaultKey, "cred-2", blob); !errors.Is(err, ErrAuthenticationFailed) {
		t.Fatalf("wrong credential id error = %v, want ErrAuthenticationFailed", err)
	}
}

func TestGeneratePasswordHonorsOptions(t *testing.T) {
	password, err := GeneratePassword(DefaultPasswordGeneratorOptions())
	if err != nil {
		t.Fatalf("generate default password: %v", err)
	}

	if len(password) != DefaultGeneratedPasswordLength {
		t.Fatalf("generated password length = %d, want %d", len(password), DefaultGeneratedPasswordLength)
	}

	assertContainsAlphabet(t, password, LowercaseAlphabet)
	assertContainsAlphabet(t, password, UppercaseAlphabet)
	assertContainsAlphabet(t, password, DigitAlphabet)
	assertContainsAlphabet(t, password, SymbolAlphabet)

	digitsOnly, err := GeneratePassword(PasswordGeneratorOptions{
		Length:        12,
		IncludeDigits: true,
	})
	if err != nil {
		t.Fatalf("generate digits-only password: %v", err)
	}

	for _, char := range digitsOnly {
		if !strings.ContainsRune(DigitAlphabet, char) {
			t.Fatalf("digits-only password contains non-digit rune %q", char)
		}
	}

	if _, err := GeneratePassword(PasswordGeneratorOptions{Length: 12}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("no alphabet error = %v, want ErrInvalidInput", err)
	}

	if _, err := GeneratePassword(PasswordGeneratorOptions{
		Length:         3,
		IncludeLower:   true,
		IncludeUpper:   true,
		IncludeDigits:  true,
		IncludeSymbols: true,
	}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("too-short length error = %v, want ErrInvalidInput", err)
	}
}

func TestValidateMasterPassword(t *testing.T) {
	policy := DefaultMasterPasswordPolicy()

	if err := ValidateMasterPassword("Very-Strong-Passphrase-2026!", policy); err != nil {
		t.Fatalf("strong password rejected: %v", err)
	}

	weakPasswords := []string{
		"short",
		"alllowercasepassword1!",
		"ALLUPPERCASEPASSWORD1!",
		"NoDigitsPassword!",
		"NoSymbolsPassword1",
	}

	for _, password := range weakPasswords {
		if err := ValidateMasterPassword(password, policy); !errors.Is(err, ErrWeakPassword) {
			t.Fatalf("weak password %q error = %v, want ErrWeakPassword", password, err)
		}
	}
}

func testKDFParams() KDFParams {
	return KDFParams{
		MemoryKiB:   MinimumKDFMemoryKiB,
		Iterations:  1,
		Parallelism: 1,
		SaltLength:  MinimumKDFSaltLength,
		KeyLength:   KeySize,
	}
}

func cloneEnvelope(envelope VaultEnvelope) VaultEnvelope {
	return VaultEnvelope{
		KDFParams:         envelope.KDFParams,
		KDFSalt:           cloneBytes(envelope.KDFSalt),
		Verifier:          cloneBytes(envelope.Verifier),
		EncryptedVaultKey: cloneBytes(envelope.EncryptedVaultKey),
		VaultKeyNonce:     cloneBytes(envelope.VaultKeyNonce),
	}
}

func assertContainsAlphabet(t *testing.T, password string, alphabet string) {
	t.Helper()

	for _, char := range password {
		if strings.ContainsRune(alphabet, char) {
			return
		}
	}

	t.Fatalf("password %q does not contain a character from alphabet %q", password, alphabet)
}
