package security

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

func RandomBytes(length int) ([]byte, error) {
	if length <= 0 {
		return nil, fmt.Errorf("%w: random byte length must be positive", ErrInvalidInput)
	}

	value := make([]byte, length)
	if _, err := rand.Read(value); err != nil {
		return nil, fmt.Errorf("read secure random bytes: %w", err)
	}

	return value, nil
}

func RandomString(length int, alphabet string) (string, error) {
	if length <= 0 {
		return "", fmt.Errorf("%w: random string length must be positive", ErrInvalidInput)
	}

	if alphabet == "" {
		return "", fmt.Errorf("%w: alphabet is required", ErrInvalidInput)
	}

	output := make([]byte, length)
	for i := range output {
		index, err := randomIndex(len(alphabet))
		if err != nil {
			return "", err
		}

		output[i] = alphabet[index]
	}

	return string(output), nil
}

func randomIndex(limit int) (int, error) {
	if limit <= 0 {
		return 0, fmt.Errorf("%w: random index limit must be positive", ErrInvalidInput)
	}

	index, err := rand.Int(rand.Reader, big.NewInt(int64(limit)))
	if err != nil {
		return 0, fmt.Errorf("generate secure random index: %w", err)
	}

	return int(index.Int64()), nil
}
