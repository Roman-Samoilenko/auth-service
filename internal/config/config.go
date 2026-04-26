package config

import (
	"os"
	"time"

	"github.com/redis/go-redis/v9"
)

type Config struct {
	HTTPPort           string
	DatabaseURL        string
	JWTSecret          string
	ContactPepper      string
	AccessTokenTTL     time.Duration
	RefreshTokenTTL    time.Duration
	RedisClient        *redis.Client
	AWSAccesKeyID      string
	AWSSecretAccessKEY string
	PostboxSender      string
	AWSRegion          string
}

func Load() *Config {
	return &Config{
		HTTPPort:        getEnv("HTTP_PORT", "8081"),
		DatabaseURL:     mustEnv("DATABASE_URL"),
		JWTSecret:       mustEnv("JWT_SECRET"),
		ContactPepper:   mustEnv("CONTACT_PEPPER"),
		AccessTokenTTL:  parseDuration(getEnv("ACCESS_TOKEN_TTL", "15m")),
		RefreshTokenTTL: parseDuration(getEnv("REFRESH_TOKEN_TTL", "168h")),
		RedisClient: redis.NewClient(&redis.Options{
			Addr: mustEnv("REDIS_ADDR")}),
		AWSAccesKeyID:      mustEnv("AWS_ACCESS_KEY_ID"),
		AWSSecretAccessKEY: mustEnv("AWS_SECRET_ACCESS_KEY"),
		PostboxSender:      mustEnv("POSTBOX_SENDER"),
		AWSRegion:          getEnv("AWS_REGION", "ru-central1"),
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
