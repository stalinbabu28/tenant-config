---
title: |
  Tenant Configuration Control Panel\
  Sprint 2 Backend
---

# Overview 

A secure and full-featured Express/Node.js backend for managing tenant
authentication configurations, admin sessions, and external service
access.

# Tech Stack 

-   Express.js --- Lightweight web framework

-   MongoDB + Mongoose --- Data modeling and persistence

-   JWT (JSON Web Tokens) --- HS256 for admin sessions, RS256 for
    machine-to-machine communication

-   Bcrypt --- Secure password hashing

-   Nodemailer --- Email delivery for MFA (OTP)

-   Cookie Parser --- HttpOnly cookie-based session management

# Project Structure 

    backend/
    ├── keys/
    │   ├── private.key
    │   └── public.key
    │
    ├── middleware/
    │   ├── auth.middleware.js
    │   ├── externalAuth.middleware.js
    │   ├── ipWhitelist.middleware.js
    │   └── rateLimit.middleware.js
    │
    ├── models/
    │   ├── Admin.js
    │   ├── AuthConfig.js
    │   └── Client.js
    │
    ├── routes/
    │   ├── auth.routes.js
    │   ├── authConfig.routes.js
    │   ├── external.routes.js
    │   └── token.routes.js
    │
    ├── utils/
    │   └── jwt.util.js
    │
    ├── .env
    ├── .gitignore
    ├── package-lock.json
    ├── package.json
    └── server.js

# Getting Started 

## 1. Install Dependencies 

``` {.bash language="bash"}
npm install
```

## 2. Generate RSA Keys 
``` {.bash language="bash"}
ssh-keygen -t rsa -b 2048 -m PEM -f keys/private.key
openssl rsa -in keys/private.key -pubout -outform PEM -out keys/public.key
```

## 3. Start the Server

``` {.bash language="bash"}
npm start
```

The server runs at:

    http://localhost:3001

# Environment Variables 

    MONGO_URI=your_mongodb_connection_string
    JWT_SECRET=your_hs256_super_secret_key
    ALLOWED_ORIGINS=http://localhost:5173
    EMAIL_USER=your_google_email@gmail.com
    EMAIL_PASS=your_google_app_password
    NODE_ENV=development

# Authentication Flows 

## Admin MFA Login (HS256) 

    POST /api/admin/login
    -> Validate password
    -> Generate OTP
    -> Send email
    -> Return session token

    POST /api/admin/verify-mfa
    -> Validate OTP and session token
    -> Set HttpOnly JWT cookie

## External Service Flow (RS256)

    POST /api/token
    -> Validate client credentials
    -> Check IP whitelist
    -> Return RS256 token

    GET /api/external/auth-config/:tenantId
    -> Validate token and scope
    -> Return tenant configuration

# Security Notes 

-   Cookies are configured as HttpOnly and Strict, and marked Secure in
    production

-   Dual JWT strategy:

    -   HS256 for admin sessions

    -   RS256 for external APIs

-   MFA uses a temporary session token with short expiration

-   Rate limiting prevents brute-force attacks

-   IP whitelisting is enforced for external clients

# Public Key (RS256) 

    -----BEGIN PUBLIC KEY-----
    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAhibLa/FFIhaCpQ4IL2yI
    J5ia+jYWZ7VRDI8pNViMm4ptln1q7qXHt/zjERDqLQF2MLN1lvjFNOucNpS2enSI
    aZUy/mdLwSvU/TjU5JwsdAK5ANLo9pqQoTvg8UCQCRn+gN1CMEhByXPSHR9QB9n4
    DIYwwkACa0TPDHA1ggbnAIVb9ZI23dxQBUOZQ9nOOvwZcHQ5JSuhY6RPYnRzRfrw
    2mkuIU9f9pd6txvqhm/lY1MOlrQJovbpoCZ5XavNh+XQfeHF5xPkWUBAAzCIUGPb
    djj1p6pc15mnOdmSWmqLOhjppxn5cz/ViOexzIZHz3aMRC7ISElPua0Ek9v0Qot0
    dwIDAQAB
    -----END PUBLIC KEY-----

# Main API Routes 

  **Endpoint**                    **Method**   **Auth Required**    **Description**
  ------------------------------- ------------ -------------------- --------------------------------------
  /api/admin/login                POST         Public               Validate credentials and trigger OTP
  /api/admin/verify-mfa           POST         Temporary Session    Validate OTP and issue JWT
  /api/admin/me                   GET          requireAuth          Return admin profile
  /api/admin/logout               POST         Public               Clear session cookie
  /api/auth-config/:tenantId      GET          requireAuth          Fetch configuration
  /api/auth-config/:tenantId      PUT          requireAuth          Update configuration
  /api/auth-config/validate       POST         requireAuth          Validate configuration rules
  /api/token                      POST         Client Credentials   Generate RS256 token
  /api/external/auth-config/:id   GET          externalAuth         Fetch configuration via M2M
