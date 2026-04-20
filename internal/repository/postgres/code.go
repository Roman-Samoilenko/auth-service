package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type CodeRepository struct {
	db *pgxpool.Pool
}

func NewCodeRepository(db *pgxpool.Pool) *CodeRepository {
	return &CodeRepository{db: db}
}

// Save сохраняет новый код подтверждения, предварительно инвалидируя старые.
func (r *CodeRepository) Save(ctx context.Context, contactHash, codeHash string, expiresAt time.Time) error {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx)

	// Инвалидируем все предыдущие неиспользованные коды для этого контакта
	_, err = tx.Exec(ctx,
		`UPDATE verification_codes SET used = TRUE
		 WHERE contact_hash = $1 AND used = FALSE`,
		contactHash,
	)
	if err != nil {
		return fmt.Errorf("invalidate old codes: %w", err)
	}

	_, err = tx.Exec(ctx,
		`INSERT INTO verification_codes (contact_hash, code_hash, expires_at)
		 VALUES ($1, $2, $3)`,
		contactHash, codeHash, expiresAt,
	)
	if err != nil {
		return fmt.Errorf("insert code: %w", err)
	}

	return tx.Commit(ctx)
}

// FindValidCodeHash возвращает хэш активного кода для данного контакта.
// Возвращает ("", false, nil) если код не найден или истёк.
func (r *CodeRepository) FindValidCodeHash(ctx context.Context, contactHash string) (string, bool, error) {
	var codeHash string
	err := r.db.QueryRow(ctx,
		`SELECT code_hash FROM verification_codes
		 WHERE contact_hash = $1
		   AND used = FALSE
		   AND expires_at > NOW()
		 ORDER BY created_at DESC
		 LIMIT 1`,
		contactHash,
	).Scan(&codeHash)

	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("find valid code: %w", err)
	}
	return codeHash, true, nil
}

// MarkUsed помечает все активные коды контакта как использованные.
func (r *CodeRepository) MarkUsed(ctx context.Context, contactHash string) error {
	_, err := r.db.Exec(ctx,
		`UPDATE verification_codes SET used = TRUE
		 WHERE contact_hash = $1 AND used = FALSE`,
		contactHash,
	)
	if err != nil {
		return fmt.Errorf("mark used: %w", err)
	}
	return nil
}
