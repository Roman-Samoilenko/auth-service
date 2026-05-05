package handler

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"auth-service/internal/config"
	"auth-service/internal/domain"
	"auth-service/internal/service"
)

type AuthHandler struct {
	svc *service.AuthService
	cfg *config.Config
}

func NewAuthHandler(svc *service.AuthService, cfg *config.Config) *AuthHandler {
	return &AuthHandler{svc: svc, cfg: cfg}
}

// POST /api/auth/send-code
// Body: {"email": "user@example.com"} ИЛИ {"phone": "+79001234567"}
func (h *AuthHandler) SendCode(w http.ResponseWriter, r *http.Request) {
	var req domain.SendCodeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if err := h.svc.SendCode(r.Context(), req); err != nil {
		switch {
		case errors.Is(err, service.ErrNoContact):
			writeError(w, http.StatusBadRequest, "email or phone is required")
		case errors.Is(err, service.ErrRateLimit):
			writeError(w, http.StatusTooManyRequests, "please wait before requesting another code")
		default:
			slog.Error("send code", "err", err)
			writeError(w, http.StatusInternalServerError, "failed to send code")
		}
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "code sent"})
}

// POST /api/auth/verify
//
// Для существующего пользователя:
//
//	{"email": "...", "code": "123456"}
//
// Для нового пользователя:
//
//	{"email": "...", "code": "123456", "nickname": "myname"}
//
// Аналогично для phone. Ответ: {"access_token": "...", "user": {...}}
// Если пользователь новый и nickname не указан — возвращает {"new_user": true}.
func (h *AuthHandler) VerifyCode(w http.ResponseWriter, r *http.Request) {
	var req domain.VerifyCodeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Code == "" {
		writeError(w, http.StatusBadRequest, "code is required")
		return
	}

	resp, refreshToken, err := h.svc.VerifyCode(r.Context(), req)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrNoContact):
			writeError(w, http.StatusBadRequest, "email or phone is required")
		case errors.Is(err, service.ErrInvalidCode):
			writeError(w, http.StatusUnauthorized, "invalid or expired code")
		case errors.Is(err, service.ErrNicknameRequired):
			// Клиент должен повторить запрос с nickname
			writeJSON(w, http.StatusOK, map[string]any{
				"new_user": true,
				"message":  "please provide a nickname to complete registration",
			})
		case errors.Is(err, service.ErrNicknameTaken):
			writeError(w, http.StatusConflict, "nickname already taken")
		default:
			slog.Error("verify code", "err", err)
			writeError(w, http.StatusInternalServerError, "internal error")
		}
		return
	}

	h.setRefreshCookie(w, refreshToken)
	writeJSON(w, http.StatusOK, resp)
}

// POST /api/auth/refresh
// Читает refresh_token из httpOnly cookie, выдаёт новую пару токенов.
func (h *AuthHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("refresh_token")
	if err != nil {
		writeError(w, http.StatusUnauthorized, "refresh token missing")
		return
	}

	resp, newRefresh, err := h.svc.RefreshTokens(r.Context(), cookie.Value)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid refresh token")
		return
	}

	h.setRefreshCookie(w, newRefresh)
	writeJSON(w, http.StatusOK, resp)
}

// POST /api/auth/logout
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    "",
		HttpOnly: true,
		Path:     "/api/auth",
		MaxAge:   -1,
	})
	writeJSON(w, http.StatusOK, map[string]string{"message": "logged out"})
}

// --- helpers ---

func (h *AuthHandler) setRefreshCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    token,
		HttpOnly: true,
		Secure:   h.cfg.CookieSecure,
		SameSite: http.SameSiteLaxMode,
		Path:     "/api/auth",
		Expires:  time.Now().Add(h.cfg.RefreshTokenTTL),
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Error("write json response", "err", err)
	}
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// GET /api/auth/config
func (h *AuthHandler) GetConfig(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"access_token_ttl_seconds":  int(h.cfg.AccessTokenTTL.Seconds()),
		"refresh_token_ttl_seconds": int(h.cfg.RefreshTokenTTL.Seconds()),
	})
}
