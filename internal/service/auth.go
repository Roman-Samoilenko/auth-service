package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"auth-service/internal/config"
	"auth-service/internal/domain"
	"auth-service/internal/repository/postgres"
	"auth-service/internal/validator"
)

var (
	ErrInvalidCode      = errors.New("invalid or expired code")
	ErrNicknameRequired = errors.New("nickname required for new users")
	ErrNicknameTaken    = errors.New("nickname already taken")
	ErrUserNotFound     = errors.New("user not found")
	ErrNoContact        = errors.New("email or phone required")
	ErrRateLimit        = errors.New("rate limit exceeded for this contact")
)

// reNonDigits — для нормализации номера телефона.
var reNonDigits = regexp.MustCompile(`\D`)

type AuthService struct {
	users  *postgres.UserRepository
	codes  *postgres.CodeRepository
	cfg    *config.Config
	mailer *LetterSender
}

func NewAuthService(
	users *postgres.UserRepository,
	codes *postgres.CodeRepository,
	cfg *config.Config,
) *AuthService {
	mailer, err := NewLetterSender(cfg)
	if err != nil {
		panic(fmt.Errorf("failed to create letter sender: %w", err))
	}

	return &AuthService{users: users, codes: codes, cfg: cfg, mailer: mailer}
}

// SendCode отправляет код подтверждения по email, телефону и т.д.
// В demo-режиме просто логирует код в stdout.
func (s *AuthService) SendCode(ctx context.Context, req domain.SendCodeRequest) error {
	contact, ctype, ok := req.ContactValue()
	if !ok {
		return ErrNoContact
	}
	contact, err := validator.ValidateAndNormalize(contact, ctype)
	if err != nil {
		return err
	}

	// Хэшируем контакт, чтобы не хранить открытые PII данные в Redis
	contactHash := s.hashContact(contact)

	if err := s.checkTargetRateLimit(ctx, contactHash, 15, time.Second); err != nil {
		return err
	}

	code := generateCode()
	codeHash := s.hashContact(code)
	expiresAt := time.Now().Add(10 * time.Minute)

	if err := s.codes.Save(ctx, contactHash, codeHash, expiresAt); err != nil {
		return fmt.Errorf("save code: %w", err)
	}

	switch ctype {
	case domain.ContactEmail:
		slog.Info("email verification code", "email", contact, "code", code)
		if s.cfg.AWSRegion == "dev" || s.cfg.AWSAccesKeyID == "dev" || s.cfg.AWSSecretAccessKEY == "dev" {
			slog.Info("dev mode: skipping email send")
			return nil
		}
		if err := s.mailer.SendVerificationCode(ctx, contact, code); err != nil {
			return fmt.Errorf("send email: %w", err)
		}
	case domain.ContactPhone:
		slog.Info("sms verification code (demo)", "phone", contact, "code", code)
	}
	return nil
}

// VerifyCode проверяет код. Если пользователь новый — регистрирует.
// Возвращает AuthResponse, refresh-token строку и ошибку.
func (s *AuthService) VerifyCode(ctx context.Context, req domain.VerifyCodeRequest) (*domain.AuthResponse, string, error) {
	contact, ctype, ok := req.ContactValue()
	if !ok {
		return nil, "", ErrNoContact
	}
	contact, err := validator.ValidateAndNormalize(contact, ctype)
	if err != nil {
		return nil, "", err
	}
	contactHash := s.hashContact(contact)

	// Проверяем код
	storedHash, found, err := s.codes.FindValidCodeHash(ctx, contactHash)
	if err != nil {
		return nil, "", err
	}
	if !found || s.hashContact(req.Code) != storedHash {
		return nil, "", ErrInvalidCode
	}

	// Ищем пользователя
	user, err := s.findUserByContact(ctx, contactHash, ctype)
	if err != nil {
		return nil, "", err
	}

	if user == nil {
		// Новый пользователь — нужен nickname
		if strings.TrimSpace(req.Nickname) == "" {
			return nil, "", ErrNicknameRequired
		}
		taken, err := s.users.NicknameExists(ctx, req.Nickname)
		if err != nil {
			return nil, "", err
		}
		if taken {
			return nil, "", ErrNicknameTaken
		}
		user, err = s.createUserByContact(ctx, contactHash, ctype, req.Nickname)
		if err != nil {
			return nil, "", err
		}
		slog.Info("user registered", "user_id", user.ID, "nickname", user.Nickname, "via", string(ctype))
	} else {
		slog.Info("user logged in", "user_id", user.ID, "nickname", user.Nickname, "via", string(ctype))
	}

	// Код верен — помечаем использованным
	resp, refreshToken, err := s.buildTokenPair(user)
	if err != nil {
		return nil, "", err
	}
	// Только после успеха помечаем код использованным
	if err := s.codes.MarkUsed(ctx, contactHash); err != nil {
		// Логируем ошибку, но пользователь уже авторизован
		slog.Error("failed to mark code as used", "err", err)
	}
	return resp, refreshToken, nil
}

// RefreshTokens проверяет refresh-токен и выдаёт новую пару.
// Обращается в БД чтобы получить актуальные данные (is_admin мог измениться).
func (s *AuthService) RefreshTokens(ctx context.Context, refreshToken string) (*domain.AuthResponse, string, error) {
	claims, err := s.parseToken(refreshToken)
	if err != nil {
		return nil, "", fmt.Errorf("invalid refresh token: %w", err)
	}
	userID := int64(claims["user_id"].(float64))
	user, err := s.users.FindByID(ctx, userID)
	if err != nil {
		return nil, "", err
	}
	if user == nil {
		return nil, "", ErrUserNotFound
	}

	return s.buildTokenPair(user)
}

// --- internal ---

// checkTargetRateLimit проверяет лимит запросов для конкретной цели (хэша почты/номера)
func (s *AuthService) checkTargetRateLimit(ctx context.Context, targetHash string, limit int, window time.Duration) error {
	key := "rl:target:" + targetHash
	rdb := s.cfg.RedisClient

	count, err := rdb.Incr(ctx, key).Result()
	if err != nil {
		slog.Error("redis target rate limit incr failed", "err", err)
		return nil // fail-open: при падении редиса пропускаем
	}

	if count == 1 {
		rdb.Expire(ctx, key, window)
	}

	if count > int64(limit) {
		return ErrRateLimit
	}

	return nil
}

func (s *AuthService) findUserByContact(ctx context.Context, hash string, ctype domain.ContactType) (*domain.User, error) {
	if ctype == domain.ContactPhone {
		return s.users.FindByPhoneHash(ctx, hash)
	}
	return s.users.FindByEmailHash(ctx, hash)
}

func (s *AuthService) createUserByContact(ctx context.Context, hash string, ctype domain.ContactType, nickname string) (*domain.User, error) {
	if ctype == domain.ContactPhone {
		return s.users.CreateWithPhone(ctx, hash, nickname)
	}
	return s.users.CreateWithEmail(ctx, hash, nickname)
}

func (s *AuthService) buildTokenPair(user *domain.User) (*domain.AuthResponse, string, error) {
	accessToken, err := s.issueToken(user, s.cfg.AccessTokenTTL)
	if err != nil {
		return nil, "", err
	}
	refreshToken, err := s.issueToken(user, s.cfg.RefreshTokenTTL)
	if err != nil {
		return nil, "", err
	}
	return &domain.AuthResponse{
		AccessToken: accessToken,
		User:        *user,
	}, refreshToken, nil
}

// --- JWT ---

type Claims struct {
	UserID   int64  `json:"user_id"`
	Nickname string `json:"nickname"`
	IsAdmin  bool   `json:"is_admin"`
	jwt.RegisteredClaims
}

func (s *AuthService) issueToken(u *domain.User, ttl time.Duration) (string, error) {
	claims := Claims{
		UserID:   u.ID,
		Nickname: u.Nickname,
		IsAdmin:  u.IsAdmin,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(ttl)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).
		SignedString([]byte(s.cfg.JWTSecret))
	if err != nil {
		return "", fmt.Errorf("sign token: %w", err)
	}
	return token, nil
}

func (s *AuthService) parseToken(tokenStr string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return []byte(s.cfg.JWTSecret), nil
	})
	if err != nil || !token.Valid {
		return nil, errors.New("invalid token")
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("invalid claims type")
	}
	return claims, nil
}

// --- helpers ---

func (s *AuthService) hashContact(contact string) string {
	h := sha256.Sum256([]byte(s.cfg.ContactPepper + contact))
	return hex.EncodeToString(h[:])
}

func generateCode() string {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		slog.Error("generate code: random read failed", "err", err)
		return "000000"
	}
	n := int(b[0])<<24 | int(b[1])<<16 | int(b[2])<<8 | int(b[3])
	if n < 0 {
		n = -n
	}
	return fmt.Sprintf("%06d", n%1_000_000)
}
