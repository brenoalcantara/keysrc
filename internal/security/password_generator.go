package security

import "fmt"

const (
	LowercaseAlphabet = "abcdefghijklmnopqrstuvwxyz"
	UppercaseAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	DigitAlphabet     = "0123456789"
	SymbolAlphabet    = "!@#$%^&*()-_=+[]{};:,.?/|~"

	DefaultGeneratedPasswordLength = 20
)

type PasswordGeneratorOptions struct {
	Length         int
	IncludeLower   bool
	IncludeUpper   bool
	IncludeDigits  bool
	IncludeSymbols bool
}

func DefaultPasswordGeneratorOptions() PasswordGeneratorOptions {
	return PasswordGeneratorOptions{
		Length:         DefaultGeneratedPasswordLength,
		IncludeLower:   true,
		IncludeUpper:   true,
		IncludeDigits:  true,
		IncludeSymbols: true,
	}
}

func GeneratePassword(options PasswordGeneratorOptions) (string, error) {
	if options.Length <= 0 {
		return "", fmt.Errorf("%w: generated password length must be positive", ErrInvalidInput)
	}

	requiredAlphabets := selectedAlphabets(options)
	if len(requiredAlphabets) == 0 {
		return "", fmt.Errorf("%w: at least one password alphabet must be selected", ErrInvalidInput)
	}

	if options.Length < len(requiredAlphabets) {
		return "", fmt.Errorf("%w: password length is smaller than selected alphabet count", ErrInvalidInput)
	}

	var combinedAlphabet string
	password := make([]byte, 0, options.Length)

	for _, alphabet := range requiredAlphabets {
		combinedAlphabet += alphabet

		value, err := RandomString(1, alphabet)
		if err != nil {
			return "", err
		}

		password = append(password, value[0])
	}

	for len(password) < options.Length {
		value, err := RandomString(1, combinedAlphabet)
		if err != nil {
			return "", err
		}

		password = append(password, value[0])
	}

	if err := secureShuffle(password); err != nil {
		return "", err
	}

	return string(password), nil
}

func selectedAlphabets(options PasswordGeneratorOptions) []string {
	var alphabets []string

	if options.IncludeLower {
		alphabets = append(alphabets, LowercaseAlphabet)
	}

	if options.IncludeUpper {
		alphabets = append(alphabets, UppercaseAlphabet)
	}

	if options.IncludeDigits {
		alphabets = append(alphabets, DigitAlphabet)
	}

	if options.IncludeSymbols {
		alphabets = append(alphabets, SymbolAlphabet)
	}

	return alphabets
}

func secureShuffle(value []byte) error {
	for i := len(value) - 1; i > 0; i-- {
		j, err := randomIndex(i + 1)
		if err != nil {
			return err
		}

		value[i], value[j] = value[j], value[i]
	}

	return nil
}
