package storage

import (
	"database/sql"
	"fmt"
	"time"
)

const timestampLayout = time.RFC3339Nano

func cloneBytes(value []byte) []byte {
	if value == nil {
		return nil
	}

	cloned := make([]byte, len(value))
	copy(cloned, value)
	return cloned
}

func formatTimestamp(value time.Time) string {
	return value.UTC().Format(timestampLayout)
}

func parseTimestamp(fieldName, value string) (time.Time, error) {
	parsed, err := time.Parse(timestampLayout, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse %s timestamp: %w", fieldName, err)
	}

	return parsed, nil
}

func formatNullableTimestamp(value *time.Time) any {
	if value == nil {
		return nil
	}

	return formatTimestamp(*value)
}

func parseNullableTimestamp(fieldName string, value sql.NullString) (*time.Time, error) {
	if !value.Valid {
		return nil, nil
	}

	parsed, err := parseTimestamp(fieldName, value.String)
	if err != nil {
		return nil, err
	}

	return &parsed, nil
}
