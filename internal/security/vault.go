package security

import "fmt"

type VaultEnvelope struct {
	KDFParams         KDFParams
	KDFSalt           []byte
	Verifier          []byte
	EncryptedVaultKey []byte
	VaultKeyNonce     []byte
}

func NewVaultEnvelope(masterPassword []byte, params KDFParams) (VaultEnvelope, []byte, error) {
	vaultKey, err := GenerateVaultKey()
	if err != nil {
		return VaultEnvelope{}, nil, err
	}

	envelope, err := NewVaultEnvelopeForVaultKey(masterPassword, params, vaultKey)
	if err != nil {
		ZeroBytes(vaultKey)
		return VaultEnvelope{}, nil, err
	}

	return envelope, vaultKey, nil
}

func NewVaultEnvelopeForVaultKey(masterPassword []byte, params KDFParams, vaultKey []byte) (VaultEnvelope, error) {
	if len(vaultKey) != KeySize {
		return VaultEnvelope{}, fmt.Errorf("%w: vault key must be %d bytes", ErrInvalidInput, KeySize)
	}

	if err := ValidateKDFParamsForCreation(params); err != nil {
		return VaultEnvelope{}, err
	}

	salt, err := GenerateSalt(params)
	if err != nil {
		return VaultEnvelope{}, err
	}

	masterKey, err := DeriveMasterKey(masterPassword, salt, params)
	if err != nil {
		ZeroBytes(salt)
		return VaultEnvelope{}, err
	}
	defer ZeroBytes(masterKey)

	subkeys, err := DeriveSubkeys(masterKey)
	if err != nil {
		ZeroBytes(salt)
		return VaultEnvelope{}, err
	}
	defer subkeys.Zero()

	verifier, err := CreateVerifier(subkeys.AuthKey)
	if err != nil {
		ZeroBytes(salt)
		return VaultEnvelope{}, err
	}

	encryptedVaultKey, err := EncryptVaultKey(subkeys.WrapKey, vaultKey)
	if err != nil {
		ZeroBytes(salt)
		ZeroBytes(verifier)
		return VaultEnvelope{}, err
	}

	envelope := VaultEnvelope{
		KDFParams:         params,
		KDFSalt:           cloneBytes(salt),
		Verifier:          verifier,
		EncryptedVaultKey: encryptedVaultKey.Ciphertext,
		VaultKeyNonce:     encryptedVaultKey.Nonce,
	}

	ZeroBytes(salt)
	return envelope, nil
}

func OpenVaultEnvelope(masterPassword []byte, envelope VaultEnvelope) ([]byte, error) {
	if err := validateVaultEnvelope(envelope); err != nil {
		return nil, err
	}

	masterKey, err := DeriveMasterKey(masterPassword, envelope.KDFSalt, envelope.KDFParams)
	if err != nil {
		return nil, err
	}
	defer ZeroBytes(masterKey)

	subkeys, err := DeriveSubkeys(masterKey)
	if err != nil {
		return nil, err
	}
	defer subkeys.Zero()

	if !VerifyVerifier(subkeys.AuthKey, envelope.Verifier) {
		return nil, fmt.Errorf("%w: verifier mismatch", ErrAuthenticationFailed)
	}

	vaultKey, err := DecryptVaultKey(subkeys.WrapKey, EncryptedBlob{
		Ciphertext: envelope.EncryptedVaultKey,
		Nonce:      envelope.VaultKeyNonce,
	})
	if err != nil {
		return nil, err
	}

	return vaultKey, nil
}

func validateVaultEnvelope(envelope VaultEnvelope) error {
	switch {
	case len(envelope.KDFSalt) < MinimumKDFSaltLength:
		return fmt.Errorf("%w: kdf salt is required", ErrInvalidInput)
	case len(envelope.Verifier) == 0:
		return fmt.Errorf("%w: verifier is required", ErrInvalidInput)
	case len(envelope.EncryptedVaultKey) == 0:
		return fmt.Errorf("%w: encrypted vault key is required", ErrInvalidInput)
	case len(envelope.VaultKeyNonce) != NonceSize:
		return fmt.Errorf("%w: vault key nonce must be %d bytes", ErrInvalidInput, NonceSize)
	default:
		return ValidateKDFParams(envelope.KDFParams)
	}
}
