package security

import (
	"fmt"
	"unicode"
	"unicode/utf8"
)

type MasterPasswordPolicy struct {
	MinLength     int
	RequireLower  bool
	RequireUpper  bool
	RequireDigit  bool
	RequireSymbol bool
}

func DefaultMasterPasswordPolicy() MasterPasswordPolicy {
	return MasterPasswordPolicy{
		MinLength:     14,
		RequireLower:  true,
		RequireUpper:  true,
		RequireDigit:  true,
		RequireSymbol: true,
	}
}

func ValidateMasterPassword(password string, policy MasterPasswordPolicy) error {
	return ValidateMasterPasswordBytes([]byte(password), policy)
}

func ValidateMasterPasswordBytes(password []byte, policy MasterPasswordPolicy) error {
	if policy.MinLength <= 0 {
		return fmt.Errorf("%w: minimum password length must be positive", ErrInvalidInput)
	}

	if bytesTrimSpace(password) == 0 {
		return fmt.Errorf("%w: password is required", ErrWeakPassword)
	}

	var hasLower bool
	var hasUpper bool
	var hasDigit bool
	var hasSymbol bool
	var length int

	for len(password) > 0 {
		char, size := utf8.DecodeRune(password)
		if char == utf8.RuneError && size == 1 {
			return fmt.Errorf("%w: password must be valid utf-8", ErrWeakPassword)
		}

		password = password[size:]
		length++

		switch {
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsDigit(char):
			hasDigit = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSymbol = true
		}
	}

	if length < policy.MinLength {
		return fmt.Errorf("%w: password must have at least %d characters", ErrWeakPassword, policy.MinLength)
	}

	if policy.RequireLower && !hasLower {
		return fmt.Errorf("%w: password must include a lowercase character", ErrWeakPassword)
	}

	if policy.RequireUpper && !hasUpper {
		return fmt.Errorf("%w: password must include an uppercase character", ErrWeakPassword)
	}

	if policy.RequireDigit && !hasDigit {
		return fmt.Errorf("%w: password must include a digit", ErrWeakPassword)
	}

	if policy.RequireSymbol && !hasSymbol {
		return fmt.Errorf("%w: password must include a symbol", ErrWeakPassword)
	}

	return nil
}

func bytesTrimSpace(value []byte) int {
	var count int
	for len(value) > 0 {
		char, size := utf8.DecodeRune(value)
		if char == utf8.RuneError && size == 1 {
			return 0
		}

		value = value[size:]
		if !unicode.IsSpace(char) {
			count++
		}
	}

	return count
}
