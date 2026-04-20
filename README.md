# Auth Service

Высокопроизводительный микросервис аутентификации на Go с кодовым входом (OTP) по email и телефону, двухуровневой JWT-системой токенов, многоуровневой защитой от перебора через Redis и privacy-first хранением персональных данных без единого открытого PII-поля в базе данных.

## Концепция и ключевые решения

Сервис реализует **passwordless-аутентификацию**: вместо классической пары логин/пароль пользователь подтверждает владение контактом одноразовым кодом. Это устраняет целый класс уязвимостей (credential stuffing, брутфорс паролей, утечки хэшей) и снижает порог входа для конечного пользователя.

**Privacy-first архитектура** — самое принципиальное решение проекта. Email и телефон никогда не сохраняются в базе данных в открытом виде. Хранится только `SHA256(pepper + contact)`. Это означает: даже при полной утечке дампа базы злоумышленник не узнает ни одного email-адреса или телефонного номера пользователей.

**Двухуровневая токенная система** — `access_token` с коротким TTL (15 минут) и `refresh_token` с длинным TTL (7 дней), доставляемый исключительно через httpOnly cookie. Access-токен никогда не покидает тело ответа и не сохраняется на сервере: сервис является stateless относительно сессий.

**Многоуровневая защита от злоупотреблений** — два независимых слоя rate limiting: по IP-адресу на уровне роутера (Redis) и по хэшу контакта на уровне бизнес-логики. Атака на чужой номер телефона ограничена вне зависимости от количества IP-адресов атакующего.

## Обзор архитектуры

```mermaid
graph TB
    subgraph "External Clients"
        Web[Web Application]
        Mobile[Mobile Client]
        GW[API Gateway / Nginx]
    end

    subgraph "Auth Service"
        subgraph "Transport Layer"
            Router[chi Router<br/>Middleware Chain]
        end

        subgraph "Handler Layer"
            SendCode[SendCode Handler<br/>POST /api/auth/send-code]
            VerifyCode[VerifyCode Handler<br/>POST /api/auth/verify]
            Refresh[Refresh Handler<br/>POST /api/auth/refresh]
            Logout[Logout Handler<br/>POST /api/auth/logout]
            Health[Health Handler<br/>GET /health]
        end

        subgraph "Service Layer"
            AuthSvc[AuthService<br/>Business Logic]
            Validator[Contact Validator<br/>Email / Phone Normalizer]
            JWTEngine[JWT Engine<br/>HS256 Signer]
            RateLimiter[Rate Limiter<br/>Target-level]
        end

        subgraph "Repository Layer"
            UserRepo[UserRepository<br/>pgx/v5]
            CodeRepo[CodeRepository<br/>pgx/v5]
        end
    end

    subgraph "Infrastructure"
        Redis[(Redis<br/>Rate Limiting<br/>Sliding Window)]
        Postgres[(PostgreSQL 16<br/>users<br/>verification_codes)]
    end

    Web & Mobile -->|HTTP/HTTPS| GW
    GW -->|Proxy| Router
    Router -->|Route| SendCode & VerifyCode & Refresh & Logout & Health
    SendCode & VerifyCode & Refresh & Logout --> AuthSvc
    AuthSvc --> Validator
    AuthSvc --> JWTEngine
    AuthSvc --> RateLimiter
    AuthSvc --> UserRepo & CodeRepo
    RateLimiter -->|INCR / EXPIRE| Redis
    Router -->|IP rate limit| Redis
    UserRepo & CodeRepo -->|pgxpool| Postgres

    style AuthSvc fill:#e27a4a,stroke:#c96021,color:#fff
    style Router fill:#4a90e2,stroke:#2171c9,color:#fff
    style Redis fill:#dc382d,stroke:#a82620,color:#fff
    style Postgres fill:#336791,stroke:#1a3f5c,color:#fff
```

## Технологический стек

### Ядро сервиса

| Компонент | Технология | Версия | Обоснование выбора |
|-----------|-----------|--------|-------------------|
| **Runtime** | Go | 1.24+ | Нативная конкурентность, минимальный footprint, предсказуемая latency |
| **HTTP Router** | chi | v5 | Идиоматический Go, middleware chain, zero allocation routing |
| **JWT** | golang-jwt/jwt | v5 | Активно поддерживаемая реализация, поддержка `RegisteredClaims` |
| **DB Driver** | pgx | v5 | Нативный PostgreSQL протокол, connection pool из коробки |
| **Redis Client** | go-redis | v9 | Поддержка Redis 7+, context-aware операции |
| **Logging** | log/slog | stdlib | Структурированные JSON-логи без зависимостей |

### Инфраструктура

| Технология | Роль | Особенности использования |
|------------|------|--------------------------|
| **PostgreSQL 16** | Персистентное хранилище | Только хэши PII, частичные индексы, pgcrypto extension |
| **Redis 7** | Rate limiting | Sliding window через INCR + EXPIRE, fail-open при недоступности |
| **Docker** | Контейнеризация | Multi-stage build, минимальный образ на alpine |

### Криптография

| Алгоритм | Применение | Параметры |
|----------|-----------|-----------|
| **HMAC-SHA256** | Подпись JWT токенов | Секрет из переменной окружения, ротируемый |
| **SHA256** | Хэширование контактов | С pepper-ом, детерминированный для lookup-а |
| **CSPRNG** | Генерация OTP кодов | `crypto/rand`, 6 цифр, равномерное распределение |

## Структура проекта

```text
auth-service/
├── cmd/
│   └── auth/
│       └── main.go                  # Точка входа: инициализация зависимостей
│
├── internal/
│   ├── config/
│   │   └── config.go                # Конфигурация из env с валидацией
│   │
│   ├── domain/
│   │   └── user.go                  # Доменные типы: User, SendCodeRequest, VerifyCodeRequest
│   │
│   ├── handler/
│   │   ├── auth.go                  # HTTP-хэндлеры аутентификации
│   │   ├── middleware.go            # IP-based rate limiting middleware
│   │   └── router.go                # chi роутер с настройкой маршрутов
│   │
│   ├── repository/
│   │   └── postgres/
│   │       ├── db.go                # pgxpool factory
│   │       ├── user.go              # UserRepository: find, create, exists
│   │       └── code.go              # CodeRepository: save, find, mark used
│   │
│   ├── service/
│   │   └── auth.go                  # AuthService: бизнес-логика, JWT, хэширование
│   │
│   └── validator/
│       └── contact.go               # Валидация и нормализация email/phone
│
├── migrations/
│   └── 000001_init.up.sql           # Схема БД: users, verification_codes, индексы
│
├── Dockerfile
└── docker-compose.yaml
```

## Компоненты системы

### Transport Layer — chi Router

Точка входа для всех HTTP-запросов с настроенной цепочкой middleware и дифференцированными лимитами по эндпоинтам.

**Middleware chain:**

```
RealIP → Logger → Recoverer → ipRateLimiter(per-route)
```

`RealIP` — корректно извлекает реальный IP из заголовков `X-Forwarded-For` / `X-Real-IP` при работе за reverse proxy.

`Logger` — структурированное логирование каждого запроса: метод, путь, статус, latency.

`Recoverer` — перехват паник с возвратом `500 Internal Server Error` без крэша процесса.

`ipRateLimiter` — rate limiting по IP через Redis с настраиваемым лимитом и окном для каждого эндпоинта.

**Дифференцированные лимиты:**

| Эндпоинт | Лимит | Окно | Обоснование |
|----------|-------|------|-------------|
| `POST /api/auth/send-code` | 15 req | 1 сек | Флуд SMS/email через разные IP |
| `POST /api/auth/verify` | 2 req | 1 сек | Брутфорс кодов |
| `POST /api/auth/refresh` | 3 req | 1 сек | Авторизованные операции |
| `POST /api/auth/logout` | 5 req | 1 сек | Низкий риск |
| `GET /health` | 2 req | 1 сек | Защита от DDoS на probe-эндпоинт |

### Service Layer — AuthService

Центральный компонент бизнес-логики с полным разделением ответственности от транспортного и данных слоёв.

**Архитектура сервиса:**

```mermaid
graph TD
    subgraph "AuthService"
        SendCode[SendCode]
        VerifyCode[VerifyCode]
        RefreshTokens[RefreshTokens]

        subgraph "Internal Methods"
            HashContact[hashContact<br/>SHA256 + pepper]
            CheckRateLimit[checkTargetRateLimit<br/>Redis INCR]
            FindUser[findUserByContact<br/>email/phone dispatch]
            CreateUser[createUserByContact<br/>email/phone dispatch]
            BuildPair[buildTokenPair<br/>access + refresh]
            IssueToken[issueToken<br/>JWT HS256]
            ParseToken[parseToken<br/>verification]
        end
    end

    SendCode --> HashContact
    SendCode --> CheckRateLimit
    SendCode --> CodeRepo[(CodeRepository)]

    VerifyCode --> HashContact
    VerifyCode --> CodeRepo
    VerifyCode --> FindUser
    VerifyCode --> CreateUser
    VerifyCode --> BuildPair

    RefreshTokens --> ParseToken
    RefreshTokens --> UserRepo[(UserRepository)]
    RefreshTokens --> BuildPair

    BuildPair --> IssueToken
    CheckRateLimit --> Redis[(Redis)]
    FindUser --> UserRepo
    CreateUser --> UserRepo
```

### Repository Layer

Слой доступа к данным построен на `pgx/v5` с использованием connection pool через `pgxpool.Pool`. Все операции context-aware с корректной обработкой `pgx.ErrNoRows`.

**UserRepository:**

- `FindByEmailHash` / `FindByPhoneHash` — поиск пользователя по хэшу контакта. Возвращает `(nil, nil)` если не найден — явный сигнал отсутствия пользователя без использования ошибок для управления потоком.
- `FindByID` — поиск при refresh операции, гарантирует что данные пользователя (например, `is_admin`) всегда актуальны.
- `NicknameExists` — атомарная проверка занятости никнейма через `SELECT EXISTS`.
- `CreateWithEmail` / `CreateWithPhone` — создание пользователя с `RETURNING`, возвращает полный объект без дополнительного SELECT.

**CodeRepository:**

- `Save` — транзакционная операция: сначала инвалидирует все предыдущие коды контакта (`UPDATE ... SET used=TRUE`), затем вставляет новый. Предотвращает накопление активных кодов.
- `FindValidCodeHash` — возвращает хэш актуального кода с фильтрацией по `used=FALSE AND expires_at > NOW()`, сортировкой `ORDER BY created_at DESC LIMIT 1`.
- `MarkUsed` — вызывается только после успешной авторизации, помечает коды как использованные.

### Validator

Нормализация контактных данных перед хэшированием обеспечивает детерминированность: одинаковые адреса в разных форматах дают одинаковый хэш.

- **Email:** `strings.ToLower` + `strings.TrimSpace` + RFC-совместимая валидация regex, ограничение длины в 254 символа.
- **Phone:** удаление всех нецифровых символов, добавление `+` префикса, валидация по E.164 формату (`+` и 7–14 цифр после кода страны).

## Потоки данных

### Отправка кода подтверждения

```mermaid
sequenceDiagram
    participant C as Client
    participant H as Handler
    participant MW as ipRateLimiter
    participant S as AuthService
    participant V as Validator
    participant Redis
    participant DB as CodeRepository

    C->>H: POST /api/auth/send-code<br/>{"email": "user@example.com"}
    H->>MW: Check IP rate limit
    MW->>Redis: INCR rl:ip:{ip}
    Redis-->>MW: count
    alt count > 15/sec
        MW-->>C: 429 Too Many Requests
    end

    H->>S: SendCode(req)
    S->>V: ValidateAndNormalize(contact)
    V-->>S: normalized contact

    S->>S: SHA256(pepper + contact) = contactHash
    S->>Redis: INCR rl:target:{contactHash}
    Redis-->>S: count

    alt count > 15/sec
        S-->>H: ErrRateLimit
        H-->>C: 429 Too Many Requests
    end

    S->>S: crypto/rand → 6-digit code
    S->>S: SHA256(pepper + code) = codeHash

    S->>DB: BEGIN TX
    DB->>DB: UPDATE codes SET used=TRUE<br/>WHERE contact_hash=? AND used=FALSE
    DB->>DB: INSERT INTO verification_codes<br/>(contactHash, codeHash, expires_at=now+10m)
    DB-->>S: COMMIT

    S->>S: log.Info("email verification code", email, code)
    S-->>H: nil
    H-->>C: 200 OK {"message": "code sent"}
```

### Верификация кода — вход / регистрация

```mermaid
sequenceDiagram
    participant C as Client
    participant H as Handler
    participant S as AuthService
    participant UserRepo as UserRepository
    participant DB as PostgreSQL

    C->>H: POST /api/auth/refresh
    Note over C,H: Cookie refresh_token

    H->>H: r.Cookie("refresh_token")
    
    alt Cookie missing
        H-->>C: 401 Unauthorized
    end

    H->>S: RefreshTokens(refreshToken)
    
    S->>S: jwt.Parse with HS256

    alt Token invalid or expired
        S-->>H: error
        H-->>C: 401 Unauthorized
    end

    S->>S: extract userID from claims
    S->>UserRepo: FindByID(userID)
    
    DB-->>UserRepo: current user state
    
    Note over S,DB: DB query ensures actual is_admin flag

    alt User not found
        S-->>H: ErrUserNotFound
        H-->>C: 401 Unauthorized
    end

    S->>S: buildTokenPair
    
    S-->>H: AuthResponse with newRefreshToken
    
    H->>H: Set-Cookie refresh_token
    
    H-->>C: 200 OK
    Note right of H: access_token and user data
```

### Обновление пары токенов

```mermaid
sequenceDiagram
    participant C as Client
    participant H as Handler
    participant S as AuthService
    participant UserRepo as UserRepository
    participant DB as PostgreSQL

    C->>H: POST /api/auth/refresh
    Note over C,H: Cookie refresh_token

    H->>H: r.Cookie(refresh_token)
    
    alt Cookie missing
        H-->>C: 401 Unauthorized
    end

    H->>S: RefreshTokens(refreshToken)
    
    S->>S: jwt.Parse with HS256

    alt Token invalid or expired
        S-->>H: error
        H-->>C: 401 Unauthorized
    end

    S->>S: extract userID from claims
    S->>UserRepo: FindByID(userID)
    
    DB-->>UserRepo: user state
    
    Note over S,DB: DB query ensures actual is_admin flag

    alt User not found
        S-->>H: ErrUserNotFound
        H-->>C: 401 Unauthorized
    end

    S->>S: buildTokenPair
    
    S-->>H: AuthResponse
    
    H->>H: Set-Cookie
    
    H-->>C: 200 OK
  ```

## Безопасность

### Privacy-First хранение данных

Ключевой принцип проекта — **zero PII в базе данных**. Ни email, ни номер телефона не сохраняются нигде в открытом виде.

```

email "<user@example.com>"
         ↓
lowercase + trim → "<user@example.com>"
         ↓
SHA256(pepper + "<user@example.com>") → "a3f9d1..." (64 hex chars)
         ↓
сохраняется в колонку email_hash
```


**Почему SHA256, а не bcrypt:**
bcrypt намеренно медленный — это не подходит для lookup-операций при каждом входе. SHA256 с pepper обеспечивает достаточную защиту: без знания pepper значение хэша бесполезно, радужные таблицы неприменимы.

**Pepper vs Salt:**

- Salt хранится в БД рядом с хэшем (защищает от rainbow tables для конкретного дампа).
- Pepper хранится отдельно в environment variable (защищает от утечки дампа целиком — без pepper хэши невалидны).

### Многоуровневая защита от злоупотреблений

```mermaid
graph LR
    subgraph L1["Layer 1: IP Rate Limiting"]
        IP[IP Address]
        Redis1[Redis<br/>rl:ip:addr]
        IP -->|INCR| Redis1
    end

    subgraph L2["Layer 2: Target Rate Limiting"]
        Contact[Contact Hash]
        Redis2[Redis<br/>rl:target:hash]
        Contact -->|INCR| Redis2
    end

    subgraph L3["Layer 3: Code Expiry"]
        Code[OTP Code]
        DB[(PostgreSQL<br/>expires_at<br/>used flag)]
        Code -->|verify| DB
    end

    subgraph L4["Layer 4: Code Rotation"]
        NewCode[New Code Request]
        Invalidate[Invalidate<br/>Previous Codes]
        NewCode -->|triggers| Invalidate
    end

    Attack[Attacker] -->|blocked by| IP
    Attack -->|blocked by| Contact
    Attack -->|blocked by| Code
    Attack -->|blocked by| NewCode
```

**Сценарий атаки и защита:**

| Сценарий | Механизм защиты | Поведение |
|----------|----------------|-----------|
| Флуд SMS с одного IP | Layer 1: ipRateLimiter | 429 после 15 req/sec с IP |
| Флуд SMS на чужой номер с разных IP | Layer 2: Target rate limit | 429 после 15 req/sec на номер |
| Брутфорс 6-значного кода | Layer 3: Code expiry + Layer 1 | 10 мин TTL + 2 req/sec на verify |
| Накопление активных кодов | Layer 4: Code rotation | Новый код инвалидирует предыдущие |
| Кража refresh-токена | httpOnly cookie | Недоступен через `document.cookie` / XSS |
| Устаревшие данные в access-токене | DB lookup при refresh | `is_admin` всегда актуален |

**Fail-open принцип для Redis:**
Оба уровня rate limiting используют `fail-open` стратегию — при недоступности Redis запрос пропускается. Это осознанный trade-off: доступность сервиса приоритетнее временного отсутствия rate limiting.

### JWT архитектура

```mermaid
graph LR
    subgraph "Access Token (15 min)"
        AT[Header.Payload.Signature<br/>HS256]
        AT_Claims["Claims:<br/>user_id: int64<br/>nickname: string<br/>is_admin: bool<br/>exp: now+15m<br/>iat: now"]
    end

    subgraph "Refresh Token (7 days)"
        RT[Header.Payload.Signature<br/>HS256]
        RT_Claims["Claims:<br/>user_id: int64<br/>nickname: string<br/>is_admin: bool<br/>exp: now+168h<br/>iat: now"]
        Cookie["httpOnly Cookie<br/>Path: /auth<br/>SameSite: Lax"]
        RT --> Cookie
    end

    subgraph "Token Delivery"
        Body["Response Body<br/>{access_token, user}"]
        AT --> Body
    end

    subgraph "Downstream Services"
        Verify["Verify Signature<br/>Extract Claims<br/>Stateless"]
    end

    AT --> Verify
```

Access-токен передаётся в теле ответа и используется downstream-сервисами для stateless авторизации без обращения к auth-сервису. Refresh-токен доступен только через `/api/auth/refresh` благодаря ограничению `Path=/auth`.

## База данных

### Схема

```sql
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

CREATE TABLE verification_codes (
    id            BIGSERIAL PRIMARY KEY,
    contact_hash  CHAR(64) NOT NULL,
    code_hash     CHAR(64) NOT NULL,
    expires_at    TIMESTAMPTZ NOT NULL,
    used          BOOLEAN NOT NULL DEFAULT FALSE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

### Индексы и их обоснование

```sql
-- Частичные индексы: не индексируют NULL-значения (email_hash или phone_hash)
CREATE INDEX idx_users_email_hash ON users(email_hash) WHERE email_hash IS NOT NULL;
CREATE INDEX idx_users_phone_hash ON users(phone_hash) WHERE phone_hash IS NOT NULL;

-- Индекс для всех запросов к кодам конкретного контакта
CREATE INDEX idx_vcodes_contact ON verification_codes(contact_hash);

-- Частичный индекс только по неиспользованным кодам — основной lookup
CREATE INDEX idx_vcodes_active ON verification_codes(contact_hash) WHERE used = FALSE;
```

Частичный индекс `idx_vcodes_active` критичен для производительности: при высокой нагрузке таблица `verification_codes` растёт быстро, но активных (неиспользованных) кодов всегда мало. Индекс поддерживает только их, что снижает его размер и время обновления.

### ER-диаграмма

```mermaid
erDiagram
    USERS {
        bigserial id PK
        char_64 email_hash UK "nullable"
        char_64 phone_hash UK "nullable"
        varchar_50 nickname UK
        boolean is_admin
        timestamptz created_at
    }

    VERIFICATION_CODES {
        bigserial id PK
        char_64 contact_hash "indexed"
        char_64 code_hash
        timestamptz expires_at
        boolean used
        timestamptz created_at
    }

    USERS ||--o{ VERIFICATION_CODES : "contact_hash links logically"
```

Связь между таблицами намеренно является **логической, не декларативной**: внешний ключ отсутствует, так как `contact_hash` в `verification_codes` существует до создания пользователя — коды запрашиваются ещё до регистрации.

## API документация

### Отправка кода подтверждения

**Request:**

```http
POST /api/auth/send-code HTTP/1.1
Content-Type: application/json

{"email": "user@example.com"}
```

или по телефону:

```http
POST /api/auth/send-code HTTP/1.1
Content-Type: application/json

{"phone": "+79001234567"}
```

**Response (success):**

```http
HTTP/1.1 200 OK
Content-Type: application/json

{"message": "code sent"}
```

**Response (rate limited):**

```http
HTTP/1.1 429 Too Many Requests
Content-Type: application/json

{"error": "please wait before requesting another code"}
```

### Верификация кода

**Существующий пользователь:**

```http
POST /api/auth/verify HTTP/1.1
Content-Type: application/json

{
  "email": "user@example.com",
  "code": "491823"
}
```

**Новый пользователь:**

```http
POST /api/auth/verify HTTP/1.1
Content-Type: application/json

{
  "email": "user@example.com",
  "code": "491823",
  "nickname": "john_doe"
}
```

**Response (success):**

```http
HTTP/1.1 200 OK
Set-Cookie: refresh_token=eyJ0...; HttpOnly; Path=/auth; SameSite=Lax
Content-Type: application/json

{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "id": 42,
    "nickname": "john_doe",
    "is_admin": false,
    "created_at": "2026-03-15T10:00:00Z"
  }
}
```

**Response (новый пользователь, nickname не указан):**

```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "new_user": true,
  "message": "please provide a nickname to complete registration"
}
```

**Коды ошибок:**

| HTTP Status | error | Описание |
|-------------|-------|----------|
| `400 Bad Request` | `email or phone is required` | Не передан ни email, ни phone |
| `400 Bad Request` | `invalid request body` | Невалидный JSON |
| `401 Unauthorized` | `invalid or expired code` | Неверный код или истёк TTL |
| `409 Conflict` | `nickname already taken` | Никнейм занят другим пользователем |
| `429 Too Many Requests` | `too many requests from your IP` | Превышен IP rate limit |
| `429 Too Many Requests` | `please wait before requesting another code` | Превышен target rate limit |
| `500 Internal Server Error` | `internal error` | Ошибка БД или другая внутренняя ошибка |

### Обновление токенов

```http
POST /api/auth/refresh HTTP/1.1
Cookie: refresh_token=eyJ0...
```

**Response:**

```http
HTTP/1.1 200 OK
Set-Cookie: refresh_token=eyJ0...; HttpOnly; Path=/auth; SameSite=Lax
Content-Type: application/json

{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "id": 42,
    "nickname": "john_doe",
    "is_admin": false,
    "created_at": "2026-03-15T10:00:00Z"
  }
}
```

### Выход из системы

```http
POST /api/auth/logout HTTP/1.1
```

**Response:**

```http
HTTP/1.1 200 OK
Set-Cookie: refresh_token=; HttpOnly; Path=/auth; Max-Age=-1
Content-Type: application/json

{"message": "logged out"}
```

### Health Check

```http
GET /health HTTP/1.1
```

```http
HTTP/1.1 200 OK
Content-Type: application/json

{"status": "ok"}
```

## Жизненный цикл OTP кода

```mermaid
stateDiagram-v2
    [*] --> Created: POST /send-code

    Created --> Active: Saved to DB\nused=FALSE
    Active --> Expired: expires_at passed\n(10 minutes)
    Active --> Used: POST /verify\ncode correct
    Active --> Invalidated: New /send-code\nfor same contact

    Expired --> [*]: Filtered by\nexpires_at > NOW()
    Used --> [*]: used=TRUE
    Invalidated --> [*]: used=TRUE

    note right of Active
        FindValidCodeHash
        checks:
        - used = FALSE
        - expires_at > NOW()
        - ORDER BY created_at DESC
        - LIMIT 1
    end note
```

## Жизненный цикл пользователя

```mermaid
stateDiagram-v2
    [*] --> CodeRequested: POST /send-code
    CodeRequested --> CodeVerified: Code correct

    CodeVerified --> NicknameRequired: User not found
    NicknameRequired --> Registered: POST /verify\nwith nickname
    CodeVerified --> LoggedIn: User exists

    Registered --> LoggedIn: JWT pair issued

    LoggedIn --> TokenRefreshed: POST /refresh\nvalid cookie
    TokenRefreshed --> LoggedIn: New pair issued

    LoggedIn --> LoggedOut: POST /logout
    LoggedOut --> [*]: Cookie cleared

    LoggedIn --> SessionExpired: access_token\nexpires (15 min)
    SessionExpired --> TokenRefreshed: Client uses\nrefresh cookie

    TokenRefreshed --> LoggedOut: refresh_token\nexpires (7 days)
```

## Конфигурация

Все параметры передаются через переменные окружения. Сервис завершает работу с паникой при отсутствии обязательных переменных.

### Переменные окружения

| Переменная | Обязательная | Значение по умолчанию | Описание |
|-----------|:------------:|----------------------|----------|
| `DATABASE_URL` | да | — | PostgreSQL DSN: `postgres://user:pass@host:5432/db` |
| `JWT_SECRET` | да | — | Секрет HMAC-SHA256 для подписи токенов |
| `CONTACT_PEPPER` | да | — | Pepper для хэширования PII данных |
| `REDIS_ADDR` | да | — | Адрес Redis: `host:port` |
| `HTTP_PORT` | нет | `8081` | Порт HTTP-сервера |
| `ACCESS_TOKEN_TTL` | нет | `15m` | TTL access-токена (Go duration format) |
| `REFRESH_TOKEN_TTL` | нет | `168h` | TTL refresh-токена (7 дней) |

**Требования к безопасности:**

- `JWT_SECRET` — минимум 32 случайных байта в base64: `openssl rand -base64 32`
- `CONTACT_PEPPER` — минимум 32 случайных байта, хранить отдельно от дампов БД: `openssl rand -base64 32`
- В production оба секрета передавать через Kubernetes Secrets или Vault, не через `docker-compose.yaml`

### Пример конфигурации (docker-compose.yaml)

```yaml
services:
  auth-service:
    build: .
    ports:
      - "8081:8081"
    environment:
      DATABASE_URL: postgres://postgres:postgres@postgres:5432/authdb?sslmode=disable
      JWT_SECRET: ${JWT_SECRET}
      CONTACT_PEPPER: ${CONTACT_PEPPER}
      REDIS_ADDR: redis:6379
      HTTP_PORT: "8081"
      ACCESS_TOKEN_TTL: "15m"
      REFRESH_TOKEN_TTL: "168h"
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_started

  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_DB: authdb
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: postgres
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U postgres"]
      interval: 5s
      timeout: 5s
      retries: 5

  redis:
    image: redis:7-alpine
```

## Развертывание

### Локальный запуск

```bash
# Клонирование репозитория
git clone <repo-url>
cd auth-service

# Генерация секретов
export JWT_SECRET=$(openssl rand -base64 32)
export CONTACT_PEPPER=$(openssl rand -base64 32)

# Запуск инфраструктуры и сервиса
docker-compose up --build

# Применение миграций (если не настроен auto-apply)
psql $DATABASE_URL -f migrations/000001_init.up.sql
```

### Kubernetes

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: auth-service
spec:
  replicas: 3
  selector:
    matchLabels:
      app: auth-service
  template:
    spec:
      containers:
      - name: auth-service
        image: auth-service:latest
        ports:
        - containerPort: 8081
        resources:
          requests:
            memory: "128Mi"
            cpu: "100m"
          limits:
            memory: "256Mi"
            cpu: "300m"
        livenessProbe:
          httpGet:
            path: /health
            port: 8081
          initialDelaySeconds: 10
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /health
            port: 8081
          initialDelaySeconds: 5
          periodSeconds: 5
        env:
        - name: JWT_SECRET
          valueFrom:
            secretKeyRef:
              name: auth-secrets
              key: jwt-secret
        - name: CONTACT_PEPPER
          valueFrom:
            secretKeyRef:
              name: auth-secrets
              key: contact-pepper
```

### Проверка работоспособности

```bash
# Health check
curl http://localhost:8081/health

# Запрос кода (в demo-режиме код выводится в stdout)
curl -X POST http://localhost:8081/api/auth/send-code \
  -H "Content-Type: application/json" \
  -d '{"email": "test@example.com"}'

# Верификация кода (из логов) + регистрация
curl -X POST http://localhost:8081/api/auth/verify \
  -H "Content-Type: application/json" \
  -d '{"email": "test@example.com", "code": "491823", "nickname": "testuser"}'

# Обновление токена
curl -X POST http://localhost:8081/api/auth/refresh \
  --cookie "refresh_token=<token_from_previous_response>"

# Выход
curl -X POST http://localhost:8081/api/auth/logout \
  --cookie "refresh_token=<token>"
```

## Мониторинг и логирование

### Структурированные логи (JSON)

Все логи выводятся в JSON через `log/slog` с уровнем INFO и выше:

```json
{"time":"2026-03-15T10:00:00Z","level":"INFO","msg":"auth service starting","addr":":8081"}
{"time":"2026-03-15T10:00:01Z","level":"INFO","msg":"connected to database"}
{"time":"2026-03-15T10:01:00Z","level":"INFO","msg":"email verification code (demo)","email":"user@example.com","code":"491823"}
{"time":"2026-03-15T10:02:00Z","level":"INFO","msg":"user registered","user_id":1,"nickname":"testuser","via":"email"}
{"time":"2026-03-15T10:05:00Z","level":"INFO","msg":"user logged in","user_id":1,"nickname":"testuser","via":"email"}
{"time":"2026-03-15T10:05:00Z","level":"ERROR","msg":"verify code","err":"..."}
```

### Ключевые метрики для мониторинга

| Метрика | Источник | Описание |
|---------|----------|----------|
| `http_requests_total` | chi middleware Logger | Количество запросов по эндпоинтам и статусам |
| `http_request_duration_seconds` | chi middleware Logger | Latency по эндпоинтам |
| `rate_limit_triggered_total` | 429 responses | Частота срабатывания rate limiting |
| `user_registrations_total` | log `user registered` | Новые пользователи |
| `user_logins_total` | log `user logged in` | Активные входы |
| `db_pool_connections` | pgxpool.Stat | Использование connection pool |

### Интеграция с Prometheus (roadmap)

Для production добавление метрик через `prometheus/client_golang`:

```go
// Пример инструментирования chi роутера
r.Use(middleware.RequestID)
r.Use(chimiddleware.NewPrometheusMiddleware("auth_service"))
```

## Лицензия

MIT License
