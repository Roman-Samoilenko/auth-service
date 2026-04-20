package handler

import (
	"net/http"
	"time"

	"github.com/redis/go-redis/v9"
)

// ipRateLimiter защищает приложение от флуда с одного IP-адреса.
func ipRateLimiter(rdb *redis.Client, limit int, window time.Duration) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			key := "rl:ip:" + r.RemoteAddr

			count, err := rdb.Incr(ctx, key).Result()
			if err != nil {
				// Если Redis недоступен, пропускаем запрос (fail-open)
				next.ServeHTTP(w, r)
				return
			}

			if count == 1 {
				rdb.Expire(ctx, key, window)
			}

			if count > int64(limit) {
				writeError(w, http.StatusTooManyRequests, "too many requests from your IP")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
