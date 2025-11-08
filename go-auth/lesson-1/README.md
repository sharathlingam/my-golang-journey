Here’s a **README.md** you can drop into the repo. It explains only the **Go backend** (no HTML).

````markdown
# Auth From Scratch — Go (net/http)

A minimal, framework-free authentication server in Go using only the standard library (+ `bcrypt`).
It implements **email/password signup**, **login**, **JWT access tokens** (short-lived), **refresh tokens** (long-lived, cookie-based with rotation), **logout**, and a **protected** `/me` route.

---

## Why this exists

Most tutorials either:
- store JWTs in `localStorage` (XSS risk), or
- don’t rotate refresh tokens, or
- skip cookie flags and cross-origin details.

This project aims to be small but **correctly opinionated**:
- Access tokens live **in memory** on the client.
- Refresh tokens live in an **HttpOnly** cookie and are **rotated**.
- Passwords are **bcrypt**-hashed.
- Cookies are configured with sensible defaults and clear prod notes.

---

## Features (server)

- `/signup` — create user (bcrypt-hashed password).
- `/login` — verify password, issue **access JWT** (JSON) and **refresh cookie**.
- `/refresh` — rotate refresh token and issue a new access JWT.
- `/logout` — invalidate refresh token and clear cookie.
- `/me` — protected endpoint (requires `Authorization: Bearer <access>`).
- `/health` — basic health check.
- CORS for local dev.
- No DB: **in-memory** maps (swap later).

---

## Quickstart

```bash
go version   # needs Go 1.20+
go mod init auth-from-scratch
go get golang.org/x/crypto/bcrypt
go run main.go
# Server: http://localhost:8080
````

### Default ports

* Backend: `:8080`
* Frontend (any dev server): e.g., `http://localhost:3000` or `http://127.0.0.1:5500`

> The backend enables CORS for the common dev origins above. If you use a different port, add it in `withCORS`.

---

## Configuration

Inside `main.go`:

```go
var (
  jwtIssuer   = "auth-from-scratch"
  jwtAudience = "web-client"
  accessTTL   = 15 * time.Minute
  refreshTTL  = 7 * 24 * time.Hour
  jwtSecret   = []byte("replace-with-strong-secret-32bytes-min")
  cookieName  = "rt"
  cookieDomain = "" // local dev: keep "" (scopes to request host)
)
```

**Local dev**

* `cookieDomain = ""` (scopes cookie to `localhost` host automatically)
* `Secure: false` (because you’re on HTTP)
* `SameSite: Lax`

**Production**

* Serve over **HTTPS only**.
* Set `Secure: true`.
* Set a real domain:

  * Same domain: `cookieDomain = "example.com"`
  * Cross-subdomain (frontend `app.example.com`, backend `api.example.com`): `cookieDomain = ".example.com"`

> Use environment variables in real apps. Keep `jwtSecret` at least 32 random bytes.

---

## Data model (in-memory)

```go
type User struct {
  ID               string
  Email            string
  PasswordHash     []byte
  RefreshTokenHash []byte // server stores only the hash
  RefreshTokenExp  time.Time
}

var usersByEmail = map[string]*User{}
var usersByID    = map[string]*User{}
```

> Replace with a DB later. For refresh tokens, persist: `user_id`, `token_hash`, `expires_at`, `revoked_at`.

---

## Tokens

### Access token (JWT, HS256)

* Short-lived (default **15 min**).
* Includes `sub` (user ID), `iss`, `aud`, `iat`, `exp`.
* Returned in **JSON** on `/login` and `/refresh`.
* Client must send it in `Authorization: Bearer <token>`.

### Refresh token (opaque random)

* 32 random bytes → **hash** stored server-side (SHA-256).
* Raw value stored in **HttpOnly cookie** (`rt`) with expiry ~**7 days** (configurable).
* **Rotated** on every `/refresh`:

  * Old token becomes invalid.
  * New cookie is set with a new token and extended expiry.

---

## Endpoints

### `POST /signup`

Create a user.

**Request**

```json
{ "email": "a@b.com", "password": "secret123" }
```

**Response** `201`

```json
{ "message": "user created", "userId": "<id>" }
```

**cURL**

```bash
curl -i -X POST http://localhost:8080/signup \
  -H "Content-Type: application/json" \
  -d '{"email":"a@b.com","password":"secret123"}'
```

---

### `POST /login`

Verify credentials, issue access token and set refresh cookie.

**Request**

```json
{ "email": "a@b.com", "password": "secret123" }
```

**Response** `200`

```json
{
  "accessToken": "<jwt>",
  "expiresIn": 900,
  "user": { "id": "<id>", "email": "a@b.com" }
}
```

* Also sets `Set-Cookie: rt=<refresh>; HttpOnly; ...`

**cURL** (stores cookie in `cookies.txt`)

```bash
curl -i -c cookies.txt -X POST http://localhost:8080/login \
  -H "Content-Type: application/json" \
  -d '{"email":"a@b.com","password":"secret123"}'
```

---

### `GET /me` (protected)

Requires `Authorization: Bearer <access>`.

**Response** `200`

```json
{ "id": "<id>", "email": "a@b.com" }
```

**cURL** (assuming you saved the JWT to `$AT`)

```bash
curl -i http://localhost:8080/me \
  -H "Authorization: Bearer $AT"
```

If the access token is expired/invalid → `401`.

---

### `POST /refresh`

Uses the **refresh cookie** automatically (browser or `curl -b`).

**Response** `200`

```json
{ "accessToken": "<new-jwt>", "expiresIn": 900 }
```

* Also **rotates** the refresh token and sets a new cookie.

**cURL**

```bash
curl -i -b cookies.txt -c cookies.txt -X POST http://localhost:8080/refresh
```

> `-b` sends cookies, `-c` updates the cookie jar with the rotated token.

---

### `POST /logout`

Invalidates the current refresh token (server) and clears the cookie.

**Response** `200`

```json
{ "message": "logged out" }
```

**cURL**

```bash
curl -i -b cookies.txt -X POST http://localhost:8080/logout
```

---

## Auth flow (summary)

```
Signup
  client -> POST /signup (email, password)
  server -> 201

Login
  client -> POST /login
  server -> 200 + JSON { accessToken } + Set-Cookie(rt=...)

Use API
  client -> GET /me with Authorization: Bearer <access>

Access Expired
  client -> POST /refresh (cookie auto-sent)
  server -> 200 + JSON { accessToken } + Set-Cookie(new rt)

Logout
  client -> POST /logout (cookie auto-sent)
  server -> 200 and clears cookie
```

---

## CORS & Cookies (local dev)

Middleware allows these origins:

* `http://localhost:5173`
* `http://localhost:3000`
* `http://127.0.0.1:5500`

Headers:

* `Access-Control-Allow-Credentials: true`
* `Access-Control-Allow-Headers: Content-Type, Authorization`
* `Access-Control-Allow-Methods: GET,POST,OPTIONS`

**Frontend must call** `fetch(..., { credentials: "include" })` so the refresh cookie is sent.

---

## Security notes

* **Password hashing**: `bcrypt` via `golang.org/x/crypto/bcrypt` (never store raw passwords).
* **JWT storage**: keep access token **in memory** on the client; do not put it in `localStorage` if you can avoid it.
* **Refresh cookie**:

  * `HttpOnly: true` (JS cannot read it).
  * `Secure: true` **in production** (HTTPS only).
  * `SameSite: Lax` is a good default for auth flows initiated by your site. For true cross-site POSTs, consider `SameSite=None; Secure`.
* **Rotation**: every `/refresh` mints a new token. If an attacker steals a refresh token, rotation + invalidation help reduce reuse.
* **Brute force**: add rate limiting on `/login` and `/refresh` in production.
* **Secrets**: use env vars; rotate on compromise.

---

## Internals: JWT without external libs

* Header: `{"alg":"HS256","typ":"JWT"}`
* Claims: `sub`, `iss`, `aud`, `iat`, `exp`
* Sign: `HMAC-SHA256(base64url(header) + "." + base64url(payload), jwtSecret)`
* Verify:

  1. Split `header.payload.signature`
  2. Recompute HMAC and `hmac.Equal`
  3. Parse claims, check `exp` > `now`

Base64 URL-safe encoding removes padding. Decoding adds it back when needed.

---

## Swapping to a database

Replace the in-memory store with a real DB:

Tables (example):

* `users(id, email unique, password_hash, created_at)`
* `refresh_tokens(id, user_id, token_hash, expires_at, revoked_at, created_at)`

On `/refresh`:

1. Look up `token_hash` for a **match and not expired & not revoked**.
2. Mark old token as revoked.
3. Insert new token with new expiry.
4. Set new cookie.

---

## Common pitfalls

* **Cookie not sent**: you forgot `credentials: "include"` in the client, or origin isn’t whitelisted by CORS, or cookie domain/secure flags don’t match.
* **`Secure` on HTTP**: in dev, keep `Secure: false`; on HTTPS, set `true`.
* **Clock skew**: tokens expiring slightly early; allow small skew or refresh proactively.
* **Mixing domains**: set `cookieDomain` correctly. For `api.example.com` + `app.example.com`, use `.example.com`.

---

## Troubleshooting

* **See cookies in browser**: DevTools → Application → Cookies → your API origin.
* **Trace headers**: look for `Set-Cookie` on `/login` and `/refresh`.
* **401 on `/me`**: missing or expired access token; call `/refresh` and retry.
* **Refresh fails**: cookie missing/invalid/expired; you’ll need to login again.

---

## Next steps

* Persist to SQLite/Postgres.
* Add CSRF tokens **only** if you start authorizing via cookies for API calls.
* Add roles/scopes, password reset, email verification.
* Add structured logging and per-route rate limits.
* Split config to env (`JWT_SECRET`, `COOKIE_DOMAIN`, `ACCESS_TTL`, `REFRESH_TTL`, etc).

---