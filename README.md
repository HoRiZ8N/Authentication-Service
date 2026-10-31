# Authentication Service

Spring Boot facade over Keycloak. Issues and validates JWTs for the microservices.

## Architecture

| Component | Purpose |
|---|---|
| `keycloak` | Identity provider. Stores credentials in its own PostgreSQL (`keycloak-postgres`) |
| `keycloak/bcrypt-provider` | Keycloak SPI that hashes passwords with BCrypt (unique salt per password) |
| `keycloak/realm/realm.json` | Realm `shop`: roles `ADMIN`, `USER`, `SERVICE`, clients `auth-service`, `api-gateway`, `userId` claim |
| `app` | This service |

Access token (RS256) carries `userId` and `realm_access.roles`. Resource servers fetch signing keys from
`/realms/shop/protocol/openid-connect/certs`.

## Endpoints

| Method | Path | Access | Description |
|---|---|---|---|
| POST | `/api/v1/auth/login` | public | Login/password → access + refresh tokens |
| POST | `/api/v1/auth/refresh` | public | Refresh token → new token pair (refresh tokens are single-use) |
| POST | `/api/v1/auth/validate` | public | Access token → `userId`, `role`, `expiresAt` or 401 |
| POST | `/api/v1/auth/credentials` | `ADMIN`; `SERVICE` for role `USER` only | Save login/password for an existing User Service profile |

## Run

```bash
cp .env.example .env
docker compose up -d --build
```

Keycloak: http://localhost:8180, service: http://localhost:8081.
Compose creates the `microservices` network that User Service joins, so start this stack first.

The bootstrap admin (`ADMIN_LOGIN`) is bound to User Service profile `ADMIN_USER_ID`:
create that profile first with the admin token.
