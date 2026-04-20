package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"auth-service/internal/domain"
)

type UserRepository struct {
	db *pgxpool.Pool
}

func NewUserRepository(db *pgxpool.Pool) *UserRepository {
	return &UserRepository{db: db}
}

// FindByEmailHash ищет пользователя по хэшу email.
// Возвращает (nil, nil) если пользователь не найден.
func (r *UserRepository) FindByEmailHash(ctx context.Context, hash string) (*domain.User, error) {
	u := &domain.User{}
	err := r.db.QueryRow(ctx,
		`SELECT id, nickname, is_admin, created_at
		 FROM users WHERE email_hash = $1`,
		hash,
	).Scan(&u.ID, &u.Nickname, &u.IsAdmin, &u.CreatedAt)

	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("find by email hash: %w", err)
	}
	return u, nil
}

// FindByID ищет пользователя по ID (используется при refresh токена).
func (r *UserRepository) FindByID(ctx context.Context, id int64) (*domain.User, error) {
	u := &domain.User{}
	err := r.db.QueryRow(ctx,
		`SELECT id, nickname, is_admin, created_at
		 FROM users WHERE id = $1`,
		id,
	).Scan(&u.ID, &u.Nickname, &u.IsAdmin, &u.CreatedAt)

	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("find by id: %w", err)
	}
	return u, nil
}

// NicknameExists проверяет, занят ли nickname.
func (r *UserRepository) NicknameExists(ctx context.Context, nickname string) (bool, error) {
	var exists bool
	err := r.db.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM users WHERE nickname = $1)`, nickname,
	).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("check nickname: %w", err)
	}
	return exists, nil
}

// CreateWithEmail создаёт нового пользователя с email-хэшем.
func (r *UserRepository) CreateWithEmail(ctx context.Context, emailHash, nickname string) (*domain.User, error) {
	u := &domain.User{}
	err := r.db.QueryRow(ctx,
		`INSERT INTO users (email_hash, nickname)
		 VALUES ($1, $2)
		 RETURNING id, nickname, is_admin, created_at`,
		emailHash, nickname,
	).Scan(&u.ID, &u.Nickname, &u.IsAdmin, &u.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("create user: %w", err)
	}
	return u, nil
}

// FindByPhoneHash ищет пользователя по хэшу телефона.
// Возвращает (nil, nil) если не найден.
func (r *UserRepository) FindByPhoneHash(ctx context.Context, hash string) (*domain.User, error) {
	u := &domain.User{}
	err := r.db.QueryRow(ctx,
		`SELECT id, nickname, is_admin, created_at
		 FROM users WHERE phone_hash = $1`,
		hash,
	).Scan(&u.ID, &u.Nickname, &u.IsAdmin, &u.CreatedAt)

	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("find by phone hash: %w", err)
	}
	return u, nil
}

// CreateWithPhone создаёт пользователя с привязкой к телефону.
func (r *UserRepository) CreateWithPhone(ctx context.Context, phoneHash, nickname string) (*domain.User, error) {
	u := &domain.User{}
	err := r.db.QueryRow(ctx,
		`INSERT INTO users (phone_hash, nickname)
		 VALUES ($1, $2)
		 RETURNING id, nickname, is_admin, created_at`,
		phoneHash, nickname,
	).Scan(&u.ID, &u.Nickname, &u.IsAdmin, &u.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("create user with phone: %w", err)
	}
	return u, nil
}
