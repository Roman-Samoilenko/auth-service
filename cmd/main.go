package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"

	"auth-service/internal/config"
	"auth-service/internal/handler"
	"auth-service/internal/repository/postgres"
	"auth-service/internal/service"

	"github.com/redis/go-redis/v9"
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})))

	rdb := redis.NewClient(&redis.Options{
		Addr: os.Getenv("REDIS_ADDR"),
	})

	cfg := config.Load()

	ctx := context.Background()
	db, err := postgres.NewPool(ctx, cfg.DatabaseURL)
	if err != nil {
		slog.Error("failed to connect to database", "err", err)
		os.Exit(1)
	}
	defer db.Close()
	slog.Info("connected to database")

	// Dependency injection
	userRepo := postgres.NewUserRepository(db)
	codeRepo := postgres.NewCodeRepository(db)
	authSvc := service.NewAuthService(userRepo, codeRepo, rdb, cfg)
	authHandler := handler.NewAuthHandler(authSvc, cfg)
	router := handler.NewRouter(authHandler, rdb)

	addr := ":" + cfg.HTTPPort
	slog.Info("auth service starting", "addr", addr)

	if err := http.ListenAndServe(addr, router); err != nil {
		slog.Error("server stopped", "err", err)
		os.Exit(1)
	}
}
