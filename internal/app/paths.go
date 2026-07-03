package app

import (
	"fmt"
	"os"
	"path/filepath"
)

const (
	dataDirName      = "keysrc"
	databaseFileName = "keysrc.sqlite3"
)

func DataDir() (string, error) {
	baseDir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("resolve user config dir: %w", err)
	}

	return filepath.Join(baseDir, dataDirName), nil
}

func DatabasePath(dataDir string) string {
	return filepath.Join(dataDir, databaseFileName)
}

func EnsureDataDir() (string, error) {
	dataDir, err := DataDir()
	if err != nil {
		return "", err
	}

	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return "", fmt.Errorf("create data dir: %w", err)
	}

	return dataDir, nil
}
