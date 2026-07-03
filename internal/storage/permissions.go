package storage

import (
	"errors"
	"fmt"
	"os"
)

const secureFileMode os.FileMode = 0o600

func SecureDatabaseFiles(databasePath string) error {
	if databasePath == "" {
		return fmt.Errorf("secure database files: %w", ErrInvalidRecord)
	}

	paths := []string{
		databasePath,
		databasePath + "-wal",
		databasePath + "-shm",
	}

	for _, path := range paths {
		if err := chmodIfExists(path, secureFileMode); err != nil {
			return err
		}
	}

	return nil
}

func chmodIfExists(path string, mode os.FileMode) error {
	if err := os.Chmod(path, mode); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}

		return fmt.Errorf("secure file permissions for %s: %w", path, err)
	}

	return nil
}
