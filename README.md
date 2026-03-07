# Destroyer2D World API

Secure Bun API for the `WORLD` leaderboard tab.

## Features

- Local account registration with unique nickname, email and password
- Bearer access tokens signed with `Ed25519` via `jose`
- Opaque refresh tokens stored hashed with HMAC-SHA256
- Password hashing with `Argon2id`
- SQLite persistence for users, refresh tokens and best record per difficulty
- Nickname uniqueness enforced server-side
- Rate limiting, public leaderboard caching and paginated leaderboard responses

## Environment

Copy `.env.example` and fill the values:

- `TOKEN_PEPPER`: random secret used to hash local identifiers and refresh tokens
- `JWT_PRIVATE_KEY_PEM` / `JWT_PUBLIC_KEY_PEM`: Ed25519 PEM keys

Example Ed25519 key generation:

```bash
openssl genpkey -algorithm Ed25519 -out ed25519-private.pem
openssl pkey -in ed25519-private.pem -pubout -out ed25519-public.pem
```

## Run

```bash
bun install
bun run dev
```

Server routes:

- `POST /v1/auth/register`
- `POST /v1/auth/login`
- `POST /v1/auth/refresh`
- `POST /v1/profile/nickname`
- `GET /v1/profile`
- `GET /v1/leaderboards/:difficulty?page=1&pageSize=20`
- `POST /v1/leaderboards/sync`
