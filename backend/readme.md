# Tenant Configuration Control Panel - Backend

Express + MongoDB backend for multi-tenant authentication configuration, domain-level overrides, and external integrations.

## Tech Stack

- Node.js + Express 5
- MongoDB + Mongoose
- JWT (admin and external flows)
- bcrypt, cookie-parser, cors, dotenv, nodemailer, speakeasy, google-auth-library

## Current Backend Modules

backend/
|- middleware/ (auth, domain access, external auth, IP whitelist, rate limit)
|- models/ (Admin, AuthConfig, DomainAuthConfig, Domain, MailingList, User, Client)
|- routes/ (auth, auth-config, central-auth, domains, mailing-lists, external, token)
|- services/ (domain access helpers)
|- utils/ (JWT, auth config merge/validation, cycle detection, email)
|- scripts/ (domain backfill)
|- demo/ (external API demo scripts)
|- keys/ (RSA key pair for external JWT flow)
|- server.js

## Quick Start

1) Install dependencies

```bash
npm install
```

2) Configure environment in backend/.env

```env
MONGO_URI=<your-mongodb-uri>
JWT_SECRET=<your-jwt-secret>
ALLOWED_ORIGINS=http://localhost:5173
EMAIL_USER=<smtp-or-gmail-user>
EMAIL_PASS=<smtp-or-gmail-password>
GOOGLE_CLIENT_ID=<google-oauth-client-id>
GOOGLE_CLIENT_SECRET=<google-oauth-client-secret>
GOOGLE_REDIRECT_URI=<google-oauth-redirect>
FRONTEND_BASE_URL=http://localhost:5173
```

3) Generate RSA keys (for external token flow)

```bash
ssh-keygen -t rsa -b 2048 -m PEM -f keys/private.key
openssl rsa -in keys/private.key -pubout -outform PEM -out keys/public.key
```

4) Run backend

```bash
npm start
```

Backend base URL: http://localhost:3001

## API Surface (Grouped)

### Admin Auth (/api/admin)

- POST /signup
- POST /login
- POST /verify-mfa
- POST /resend-otp
- POST /logout
- GET /me

### Tenant Auth Config (/api/auth-config)

- GET /:tenantId
- PUT /:tenantId
- POST /:tenantId/cascade
- POST /validate

### Domains (/api/domains)

- POST /
- GET /
- PUT /:domainId
- DELETE /:domainId

### Mailing Lists (/api/mailing-lists)

- GET /:tenantId
- POST /
- PUT /:id

### Central Auth (/api/central-auth)

- POST /identify
- POST /signup
- POST /login
- POST /verify-otp

### External Integration

- POST /api/token/token
- GET /api/external/auth-config/:tenantId
- POST /api/external/tenant-signup

## Security Notes

- Uses cookie-based admin session handling with credentialed CORS.
- MFA flow is enforced via OTP verification before authenticated dashboard access.
- External API endpoints are protected through dedicated middleware and client token flow.
- Domain-level configuration is validated and merged with tenant defaults before use.

## Troubleshooting

- If CORS fails, verify ALLOWED_ORIGINS contains frontend URL exactly (comma-separated for multiple origins).
- If external token validation fails, regenerate keys and verify keys/private.key and keys/public.key paths.
- If auth-config cascade behaves unexpectedly, verify parentDomainId graph and run scripts/backfillDomainId.js when needed.
