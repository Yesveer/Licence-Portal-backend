# License Portal Backend

Go (Gin) API server for the WebXTerm Licensing Portal. Handles customer onboarding, license issuance/signing, and the superadmin dashboard API. Backed by MongoDB.

## Prerequisites

- Go 1.22+
- MongoDB (local instance, Docker container, or Atlas connection string)

## 1. Configure environment

Copy the example env file and fill in real values:

```bash
cp .env.example .env
```

Key variables in `.env`:

| Variable | Purpose |
|:---------|:--------|
| `PORT` | Port the API listens on (default `8080`) |
| `CORS_ORIGINS` | `*` or a comma-separated list of allowed frontend origins |
| `MONGO_URI` / `MONGO_DB` | MongoDB connection string and database name |
| `JWT_SECRET` | Long random string used to sign admin session JWTs |
| `ADMIN_EMAIL` / `ADMIN_PASSWORD` | Bootstrap superadmin account, created on first boot |
| `LICENSE_SIGNING_PRIVATE_KEY` / `LICENSE_SIGNING_PUBLIC_KEY` | Optional — leave empty to auto-generate an Ed25519 keypair on first boot |
| `SMTP_*` | Optional fallback SMTP config (overridable from the portal's Settings page) |
| `TRIAL_DAYS` / `TRIAL_MACHINE_QUOTA` | Defaults applied to new Community/trial licenses |
| `OFFLINE_GRACE_HOURS` | How long a deployment can run on a cached license if the portal is unreachable |

## 2. Start MongoDB (if you don't already have one running)

```bash
docker run -d --name license-portal-mongo -p 27017:27017 mongo:7
```

This matches the default `MONGO_URI=mongodb://localhost:27017` in `.env.example`.

## 3. Install Go dependencies

```bash
go mod download
```

## 4. Run the server

```bash
go run main.go
```

You should see:

```
license-portal backend listening on :8080
```

Health check:

```bash
curl http://localhost:8080/health
# {"ok":true,"service":"license-portal"}
```

## Optional: build a binary

```bash
go build -o license-portal-backend .
./license-portal-backend
```

## Notes

- On first boot, the superadmin account is created from `ADMIN_EMAIL` / `ADMIN_PASSWORD` in `.env` — change the password afterward from the portal.
- If `LICENSE_SIGNING_PRIVATE_KEY` / `LICENSE_SIGNING_PUBLIC_KEY` are left blank, a signing keypair is generated automatically and persisted in MongoDB; the public key is printed to the logs on startup.
