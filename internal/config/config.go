package config

import (
	"os"
	"time"
)

type Config struct {
	HTTPPort        string
	DatabaseURL     string
	JWTSecret       string
	ContactPepper   string
	AccessTokenTTL  time.Duration
	RefreshTokenTTL time.Duration
}

func Load() *Config {
	return &Config{
		HTTPPort:        getEnv("HTTP_PORT", "8081"),
		DatabaseURL:     mustEnv("DATABASE_URL"),
		JWTSecret:       mustEnv("JWT_SECRET"),
		ContactPepper:   mustEnv("CONTACT_PEPPER"),
		AccessTokenTTL:  parseDuration(getEnv("ACCESS_TOKEN_TTL", "15m")),
		RefreshTokenTTL: parseDuration(getEnv("REFRESH_TOKEN_TTL", "168h")),
	}
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func mustEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		panic("required env variable not set: " + key)
	}
	return v
}

func parseDuration(s string) time.Duration {
	d, err := time.ParseDuration(s)
	if err != nil {
		panic("invalid duration: " + s)
	}
	return d
}
