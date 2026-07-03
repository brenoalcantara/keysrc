package service

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"keysrc/internal/security"
	"keysrc/internal/storage"
)

type CredentialService struct {
	db  *sql.DB
	now func() time.Time
}

type CredentialServiceOptions struct {
	Now func() time.Time
}

type CredentialInput struct {
	Title    string
	Username string
	Password string
	URL      string
	Notes    string
	Tags     []string
}

type Credential struct {
	ID        string
	Title     string
	Username  string
	Password  string
	URL       string
	Notes     string
	Tags      []string
	CreatedAt time.Time
	UpdatedAt time.Time
}

type credentialPayload struct {
	Title    string   `json:"title"`
	Username string   `json:"username"`
	Password string   `json:"password"`
	URL      string   `json:"url"`
	Notes    string   `json:"notes"`
	Tags     []string `json:"tags"`
}

func NewCredentialService(db *sql.DB) *CredentialService {
	return NewCredentialServiceWithOptions(db, CredentialServiceOptions{})
}

func NewCredentialServiceWithOptions(db *sql.DB, options CredentialServiceOptions) *CredentialService {
	now := options.Now
	if now == nil {
		now = time.Now
	}

	return &CredentialService{
		db:  db,
		now: now,
	}
}

func (s *CredentialService) Create(ctx context.Context, session *VaultSession, input CredentialInput) (Credential, error) {
	if err := s.validateReady(session); err != nil {
		return Credential{}, err
	}

	payload, err := payloadFromInput(input)
	if err != nil {
		return Credential{}, err
	}

	id, err := newCredentialID()
	if err != nil {
		return Credential{}, err
	}

	plaintext, err := json.Marshal(payload)
	if err != nil {
		return Credential{}, fmt.Errorf("marshal credential payload: %w", err)
	}
	defer security.ZeroBytes(plaintext)

	encrypted, err := security.EncryptCredential(session.VaultKey, id, plaintext)
	if err != nil {
		return Credential{}, err
	}

	now := s.now().UTC()
	record := storage.CredentialRecord{
		ID:         id,
		Ciphertext: encrypted.Ciphertext,
		Nonce:      encrypted.Nonce,
		AADVersion: security.CryptoVersion,
		CreatedAt:  now,
		UpdatedAt:  now,
	}

	if err := storage.WithinTx(ctx, s.db, func(tx *sql.Tx) error {
		return storage.NewCredentialRepository(tx).Create(ctx, record)
	}); err != nil {
		return Credential{}, err
	}

	return credentialFromPayload(id, payload, now, now), nil
}

func (s *CredentialService) Get(ctx context.Context, session *VaultSession, id string) (Credential, error) {
	if err := s.validateReady(session); err != nil {
		return Credential{}, err
	}

	if strings.TrimSpace(id) == "" {
		return Credential{}, fmt.Errorf("%w: credential id is required", storage.ErrInvalidRecord)
	}

	record, err := storage.NewCredentialRepository(s.db).Get(ctx, id)
	if err != nil {
		return Credential{}, err
	}

	if record.DeletedAt != nil {
		return Credential{}, fmt.Errorf("get credential: %w", storage.ErrNotFound)
	}

	return decryptCredentialRecord(session, record)
}

func (s *CredentialService) List(ctx context.Context, session *VaultSession) ([]Credential, error) {
	if err := s.validateReady(session); err != nil {
		return nil, err
	}

	records, err := storage.NewCredentialRepository(s.db).ListActive(ctx)
	if err != nil {
		return nil, err
	}

	credentials := make([]Credential, 0, len(records))
	for _, record := range records {
		credential, err := decryptCredentialRecord(session, record)
		if err != nil {
			return nil, err
		}

		credentials = append(credentials, credential)
	}

	return credentials, nil
}

func (s *CredentialService) Update(ctx context.Context, session *VaultSession, id string, input CredentialInput) (Credential, error) {
	if err := s.validateReady(session); err != nil {
		return Credential{}, err
	}

	if strings.TrimSpace(id) == "" {
		return Credential{}, fmt.Errorf("%w: credential id is required", storage.ErrInvalidRecord)
	}

	payload, err := payloadFromInput(input)
	if err != nil {
		return Credential{}, err
	}

	existing, err := storage.NewCredentialRepository(s.db).Get(ctx, id)
	if err != nil {
		return Credential{}, err
	}

	if existing.DeletedAt != nil {
		return Credential{}, fmt.Errorf("update credential: %w", storage.ErrNotFound)
	}

	plaintext, err := json.Marshal(payload)
	if err != nil {
		return Credential{}, fmt.Errorf("marshal credential payload: %w", err)
	}
	defer security.ZeroBytes(plaintext)

	encrypted, err := security.EncryptCredential(session.VaultKey, id, plaintext)
	if err != nil {
		return Credential{}, err
	}

	updatedAt := s.now().UTC()
	updated := storage.CredentialRecord{
		ID:         id,
		Ciphertext: encrypted.Ciphertext,
		Nonce:      encrypted.Nonce,
		AADVersion: security.CryptoVersion,
		CreatedAt:  existing.CreatedAt,
		UpdatedAt:  updatedAt,
		DeletedAt:  existing.DeletedAt,
	}

	if err := storage.WithinTx(ctx, s.db, func(tx *sql.Tx) error {
		return storage.NewCredentialRepository(tx).Update(ctx, updated)
	}); err != nil {
		return Credential{}, err
	}

	return credentialFromPayload(id, payload, existing.CreatedAt, updatedAt), nil
}

func (s *CredentialService) Delete(ctx context.Context, session *VaultSession, id string) error {
	if err := s.validateReady(session); err != nil {
		return err
	}

	if strings.TrimSpace(id) == "" {
		return fmt.Errorf("%w: credential id is required", storage.ErrInvalidRecord)
	}

	deletedAt := s.now().UTC()
	return storage.WithinTx(ctx, s.db, func(tx *sql.Tx) error {
		return storage.NewCredentialRepository(tx).SoftDelete(ctx, id, deletedAt)
	})
}

func (s *CredentialService) GeneratePassword(options security.PasswordGeneratorOptions) (string, error) {
	return security.GeneratePassword(options)
}

func (s *CredentialService) validateReady(session *VaultSession) error {
	if s.db == nil {
		return fmt.Errorf("credential service: %w", storage.ErrInvalidRecord)
	}

	if session == nil || len(session.VaultKey) != security.KeySize {
		return fmt.Errorf("credential service: vault is locked")
	}

	return nil
}

func decryptCredentialRecord(session *VaultSession, record storage.CredentialRecord) (Credential, error) {
	plaintext, err := security.Open(session.VaultKey, security.EncryptedBlob{
		Ciphertext: record.Ciphertext,
		Nonce:      record.Nonce,
	}, security.CredentialAAD(record.ID, record.AADVersion))
	if err != nil {
		return Credential{}, err
	}
	defer security.ZeroBytes(plaintext)

	var payload credentialPayload
	if err := json.Unmarshal(plaintext, &payload); err != nil {
		return Credential{}, fmt.Errorf("unmarshal credential payload: %w", err)
	}

	return credentialFromPayload(record.ID, payload, record.CreatedAt, record.UpdatedAt), nil
}

func payloadFromInput(input CredentialInput) (credentialPayload, error) {
	payload := credentialPayload{
		Title:    strings.TrimSpace(input.Title),
		Username: strings.TrimSpace(input.Username),
		Password: input.Password,
		URL:      strings.TrimSpace(input.URL),
		Notes:    strings.TrimSpace(input.Notes),
		Tags:     normalizeTags(input.Tags),
	}

	switch {
	case payload.Title == "":
		return credentialPayload{}, fmt.Errorf("%w: credential title is required", storage.ErrInvalidRecord)
	case payload.Password == "":
		return credentialPayload{}, fmt.Errorf("%w: credential password is required", storage.ErrInvalidRecord)
	default:
		return payload, nil
	}
}

func credentialFromPayload(id string, payload credentialPayload, createdAt time.Time, updatedAt time.Time) Credential {
	return Credential{
		ID:        id,
		Title:     payload.Title,
		Username:  payload.Username,
		Password:  payload.Password,
		URL:       payload.URL,
		Notes:     payload.Notes,
		Tags:      append([]string(nil), payload.Tags...),
		CreatedAt: createdAt,
		UpdatedAt: updatedAt,
	}
}

func normalizeTags(tags []string) []string {
	normalized := make([]string, 0, len(tags))
	seen := make(map[string]bool, len(tags))

	for _, tag := range tags {
		tag = strings.TrimSpace(tag)
		if tag == "" || seen[tag] {
			continue
		}

		seen[tag] = true
		normalized = append(normalized, tag)
	}

	return normalized
}

func newCredentialID() (string, error) {
	id, err := security.RandomBytes(16)
	if err != nil {
		return "", err
	}
	defer security.ZeroBytes(id)

	return hex.EncodeToString(id), nil
}
