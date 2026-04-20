CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Пользователи. Контактные данные хранятся как SHA256(pepper+contact).
-- SHA256 выбран вместо bcrypt потому что нужен детерминированный lookup.
CREATE TABLE users (
    id          BIGSERIAL PRIMARY KEY,
    email_hash  CHAR(64) UNIQUE,   -- SHA256(pepper + lowercase(email))
    phone_hash  CHAR(64) UNIQUE,   -- SHA256(pepper + normalized_phone)
    nickname    VARCHAR(50) NOT NULL UNIQUE,
    is_admin    BOOLEAN NOT NULL DEFAULT FALSE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT users_has_contact CHECK (
        email_hash IS NOT NULL OR phone_hash IS NOT NULL
    )
);

-- Временные коды подтверждения (для входа по email/телефону).
-- Код живёт 10 минут, после использования помечается used=true.
CREATE TABLE verification_codes (
    id            BIGSERIAL PRIMARY KEY,
    contact_hash  CHAR(64) NOT NULL,        -- SHA256(pepper+contact), для поиска
    code_hash     CHAR(64) NOT NULL,        -- SHA256(pepper+code), для проверки
    expires_at    TIMESTAMPTZ NOT NULL,
    used          BOOLEAN NOT NULL DEFAULT FALSE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_users_email_hash  ON users(email_hash)  WHERE email_hash IS NOT NULL;
CREATE INDEX idx_users_phone_hash  ON users(phone_hash)  WHERE phone_hash IS NOT NULL;
CREATE INDEX idx_vcodes_contact    ON verification_codes(contact_hash);
CREATE INDEX idx_vcodes_active     ON verification_codes(contact_hash) WHERE used = FALSE;
