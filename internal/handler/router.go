package handler

import (
	"auth-service/internal/config"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

func NewRouter(auth *AuthHandler, cfg *config.Config) http.Handler {
	rdb := cfg.RedisClient
	r := chi.NewRouter()

	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	r.With(ipRateLimiter(rdb, 2, time.Second)).Get("/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	r.Route("/api/auth", func(r chi.Router) {
		r.With(ipRateLimiter(rdb, 15, time.Second)).Post("/send-code", auth.SendCode)
		r.With(ipRateLimiter(rdb, 3, time.Second)).Post("/refresh", auth.Refresh)
		r.With(ipRateLimiter(rdb, 5, time.Second)).Post("/logout", auth.Logout)
		r.With(ipRateLimiter(rdb, 2, time.Second)).Post("/verify", auth.VerifyCode)
	})

	return r
}
