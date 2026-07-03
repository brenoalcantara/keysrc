package storage

import (
	"context"
	"database/sql"
	"fmt"
)

func WithinTx(ctx context.Context, db *sql.DB, fn func(*sql.Tx) error) (err error) {
	if db == nil {
		return fmt.Errorf("begin transaction: %w", ErrInvalidRecord)
	}

	if fn == nil {
		return fmt.Errorf("begin transaction: nil callback")
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}

	defer func() {
		if recovered := recover(); recovered != nil {
			_ = tx.Rollback()
			panic(recovered)
		}

		if err != nil {
			_ = tx.Rollback()
			return
		}

		if commitErr := tx.Commit(); commitErr != nil {
			err = fmt.Errorf("commit transaction: %w", commitErr)
		}
	}()

	err = fn(tx)
	return err
}
