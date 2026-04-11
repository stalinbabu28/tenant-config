import jwt from "jsonwebtoken";
import fs from "fs";

const privateKey = fs.readFileSync("./keys/private.key");
const publicKey = fs.readFileSync("./keys/public.key");

const ADMIN_JWT_SECRET = process.env.JWT_SECRET;
const ADMIN_JWT_ISSUER = process.env.JWT_ISSUER || "tenant-config-backend";
const ADMIN_JWT_AUDIENCE = process.env.JWT_AUDIENCE || "app";

if (!ADMIN_JWT_SECRET) {
  throw new Error("JWT_SECRET is required");
}

// Generate token
export const generateServiceToken = (payload) => {
  return jwt.sign(payload, privateKey, {
    algorithm: "RS256",
    expiresIn: "10m"
  });
};

// Verify token
export const verifyServiceToken = (token) => {
  return jwt.verify(token, publicKey, {
    algorithms: ["RS256"]
  });
};

export const issueAdminToken = ({
  adminId,
  tenantId,
  role,
  authLevel,
  domainAdminId = null,
  expiresIn = "24h"
}) => {
  return jwt.sign(
    {
      adminId,
      tenantId,
      role,
      authLevel,
      domainAdminId,
      tokenType: "admin"
    },
    ADMIN_JWT_SECRET,
    {
      expiresIn,
      issuer: ADMIN_JWT_ISSUER,
      audience: ADMIN_JWT_AUDIENCE
    }
  );
};

export const verifyAdminToken = (token) => {
  const decoded = jwt.verify(token, ADMIN_JWT_SECRET, {
    issuer: ADMIN_JWT_ISSUER,
    audience: ADMIN_JWT_AUDIENCE,
    algorithms: ["HS256"]
  });

  if (decoded.tokenType !== "admin") {
    throw new Error("Invalid token type");
  }

  if (!decoded.adminId || !decoded.tenantId || !decoded.role || !decoded.authLevel) {
    throw new Error("Invalid admin token payload");
  }

  return decoded;
};

export const issueAdminMfaSessionToken = ({
  adminId,
  email,
  tenantId,
  expiresIn = "5m"
}) => {
  return jwt.sign(
    {
      adminId,
      email,
      tenantId,
      tokenType: "admin_mfa_session"
    },
    ADMIN_JWT_SECRET,
    {
      expiresIn,
      issuer: ADMIN_JWT_ISSUER,
      audience: ADMIN_JWT_AUDIENCE
    }
  );
};

export const verifyAdminMfaSessionToken = (token) => {
  const decoded = jwt.verify(token, ADMIN_JWT_SECRET, {
    issuer: ADMIN_JWT_ISSUER,
    audience: ADMIN_JWT_AUDIENCE,
    algorithms: ["HS256"]
  });

  if (decoded.tokenType !== "admin_mfa_session") {
    throw new Error("Invalid session token type");
  }

  if (!decoded.adminId || !decoded.email || !decoded.tenantId) {
    throw new Error("Invalid MFA session payload");
  }

  return decoded;
};