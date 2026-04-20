package handler

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/redis/go-redis/v9"
)

func NewRouter(auth *AuthHandler, rdb *redis.Client) http.Handler {
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
