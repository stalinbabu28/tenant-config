import express from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import mongoose from "mongoose";
import { OAuth2Client } from "google-auth-library";
import speakeasy from "speakeasy";
import User from "../models/User.js";
import { sendOTPEmail } from "../utils/email.util.js";
import { resolveAuthConfig, mapAuthConfig } from "../utils/authConfig.util.js";

const router = express.Router();

const googleOAuthClient = new OAuth2Client({
  clientId: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  redirectUri: process.env.GOOGLE_OAUTH_REDIRECT_URI,
});

const buildGoogleState = ({ tenantId, callbackUrl }) => {
  return Buffer.from(JSON.stringify({ tenantId, callbackUrl })).toString(
    "base64",
  );
};

const parseGoogleState = (value) => {
  try {
    return JSON.parse(Buffer.from(String(value), "base64").toString("utf8"));
  } catch (err) {
    return null;
  }
};

const buildRedirectUrl = (baseUrl, params = {}) => {
  const url = new URL(baseUrl, "http://localhost");
  Object.entries(params).forEach(([key, value]) => {
    if (value !== undefined && value !== null) {
      url.searchParams.set(key, String(value));
    }
  });
  const result = url.toString();
  return baseUrl.startsWith("http")
    ? result
    : result.replace("http://localhost", "");
};

const generateOTP = () =>
  Math.floor(100000 + Math.random() * 900000).toString();

const isLockedOut = (entity) =>
  !!entity.lockoutUntil && entity.lockoutUntil > new Date();

const lockoutRemainingMinutes = (entity) => {
  if (!entity.lockoutUntil) return 0;
  return Math.ceil((entity.lockoutUntil - new Date()) / 60000);
};

router.get("/config", async (req, res) => {
  try {
    const { tenantId, domainId } = req.query;
    if (!tenantId || typeof tenantId !== "string") {
      return res.status(400).json({
        success: false,
        message: "tenantId is required",
      });
    }

    const tenantObjectId = new mongoose.Types.ObjectId(tenantId);
    const domainObjectId =
      typeof domainId === "string" && domainId
        ? new mongoose.Types.ObjectId(domainId)
        : null;
    const authConfig = await resolveAuthConfig(tenantObjectId, domainObjectId);

    res.json({
      success: true,
      data: {
        authConfig: mapAuthConfig(authConfig),
        domainId: domainObjectId?.toString() ?? null,
      },
    });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

router.post("/identify", async (req, res) => {
  try {
    const { tenantId, email, domainId } = req.body;
    if (!tenantId || !email) {
      return res.status(400).json({
        success: false,
        message: "tenantId and email are required",
      });
    }

    const tenantObjectId = new mongoose.Types.ObjectId(tenantId);
    const requestedDomainId = domainId
      ? new mongoose.Types.ObjectId(domainId)
      : null;
    const user = await User.findOne({ email, tenantId: tenantObjectId });

    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found for this tenant",
      });
    }

    if (isLockedOut(user)) {
      const minutes = lockoutRemainingMinutes(user);
      return res.status(403).json({
        success: false,
        message: `Account locked. Try again in ${minutes} minute${
          minutes === 1 ? "" : "s"
        }.`,
      });
    }

    const authConfig = await resolveAuthConfig(
      tenantObjectId,
      requestedDomainId,
    );

    res.json({
      success: true,
      data: {
        email: user.email,
        tenantId,
        domainId: requestedDomainId?.toString() ?? null,
        role: user.role,
        authConfig: mapAuthConfig(authConfig),
      },
    });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

router.post("/signup", async (req, res) => {
  try {
    const { tenantId, name, email, password } = req.body;
    if (!tenantId || !name || !email || !password) {
      return res.status(400).json({
        success: false,
        message: "tenantId, name, email, and password are required",
      });
    }

    const tenantObjectId = new mongoose.Types.ObjectId(tenantId);
    const existingUser = await User.findOne({
      email,
      tenantId: tenantObjectId,
    });
    if (existingUser) {
      return res.status(409).json({
        success: false,
        message: "A user with this email already exists for the tenant.",
      });
    }

    // Validate password against policy
    const authConfig = await resolveAuthConfig(tenantObjectId, null);
    if (!authConfig) {
      return res.status(400).json({
        success: false,
        message: "Auth configuration not found for tenant.",
      });
    }

    const { passwordPolicy } = authConfig;
    if (password.length < passwordPolicy.minLength) {
      return res.status(400).json({
        success: false,
        message: `Password must be at least ${passwordPolicy.minLength} characters long.`,
      });
    }
    if (passwordPolicy.requireUppercase && !/[A-Z]/.test(password)) {
      return res.status(400).json({
        success: false,
        message: "Password must contain at least one uppercase letter.",
      });
    }
    if (passwordPolicy.requireNumbers && !/\d/.test(password)) {
      return res.status(400).json({
        success: false,
        message: "Password must contain at least one number.",
      });
    }
    if (
      passwordPolicy.requireSpecialChar &&
      !/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)
    ) {
      return res.status(400).json({
        success: false,
        message: "Password must contain at least one special character.",
      });
    }

    const passwordHash = await bcrypt.hash(password, 10);
    await User.create({
      name,
      email,
      passwordHash,
      tenantId: tenantObjectId,
      domainId: null,
      role: "USER",
    });

    res.json({
      success: true,
      message: "User account created. You can now sign in.",
    });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

router.post("/login", async (req, res) => {
  try {
    const { tenantId, email, password, domainId } = req.body;
    if (!tenantId || !email) {
      return res.status(400).json({
        success: false,
        message: "tenantId and email are required",
      });
    }

    const tenantObjectId = new mongoose.Types.ObjectId(tenantId);
    const requestedDomainId = domainId
      ? new mongoose.Types.ObjectId(domainId)
      : null;
    const user = await User.findOne({ email, tenantId: tenantObjectId });

    if (!user) {
      return res
        .status(401)
        .json({ success: false, message: "Invalid credentials" });
    }

    if (isLockedOut(user)) {
      const minutes = lockoutRemainingMinutes(user);
      return res.json({
        success: false,
        message: `Account locked. Try again in ${minutes} minute${
          minutes === 1 ? "" : "s"
        }.`,
      });
    }

    const authConfig = await resolveAuthConfig(
      tenantObjectId,
      requestedDomainId,
    );

    if (
      !authConfig.loginMethods.emailPassword &&
      authConfig.loginMethods.googleSSO
    ) {
      return res.json({
        success: true,
        message: "Use SSO to sign in.",
        data: { requiresSSO: true },
      });
    }

    if (authConfig.loginMethods.emailPassword) {
      if (!password) {
        return res.status(400).json({
          success: false,
          message: "Password is required for this tenant configuration",
        });
      }

      const validPassword = await bcrypt.compare(password, user.passwordHash);
      if (!validPassword) {
        user.failedLoginAttempts += 1;
        if (
          authConfig.sessionRules.maxLoginAttempts > 0 &&
          user.failedLoginAttempts >= authConfig.sessionRules.maxLoginAttempts
        ) {
          user.lockoutUntil = new Date(
            Date.now() + authConfig.sessionRules.lockoutDurationMinutes * 60000,
          );
          await user.save();
          return res.json({
            success: false,
            message: `Account locked for ${authConfig.sessionRules.lockoutDurationMinutes} minutes after ${authConfig.sessionRules.maxLoginAttempts} failed attempt${
              authConfig.sessionRules.maxLoginAttempts === 1 ? "" : "s"
            }.`,
          });
        }

        await user.save();
        return res
          .status(401)
          .json({ success: false, message: "Invalid credentials" });
      }

      user.failedLoginAttempts = 0;
      user.lockoutUntil = null;

      if (authConfig.loginMethods.otpLogin && !authConfig.mfa.enabled) {
        const otp = generateOTP();
        user.otp = otp;
        user.otpExpiry = new Date(Date.now() + 5 * 60 * 1000);
        user.lastActivityAt = new Date();
        await user.save();

        try {
          await sendOTPEmail(user.email, otp);
        } catch (sendErr) {
          return res.status(500).json({
            success: false,
            message: "Unable to deliver OTP email",
          });
        }

        const sessionToken = jwt.sign(
          {
            email: user.email,
            tenantId,
            domainId: user.domainId ?? null,
          },
          process.env.JWT_SECRET,
          {
            expiresIn: "5m",
          },
        );

        return res.json({
          success: true,
          message: "OTP has been sent to your email.",
          data: {
            requiresMFA: true,
            sessionToken,
          },
        });
      }
    } else if (!authConfig.loginMethods.otpLogin) {
      return res.status(403).json({
        success: false,
        message: "No supported login method is enabled for this tenant",
      });
    }

    const sessionToken = jwt.sign(
      {
        email: user.email,
        tenantId,
        domainId: user.domainId ?? null,
      },
      process.env.JWT_SECRET,
      {
        expiresIn: "5m",
      },
    );

    if (authConfig.mfa.enabled) {
      if (!user.totpSecret) {
        const secret = speakeasy.generateSecret({
          name: `TenantConfig (${user.email})`,
        });
        user.totpSecret = secret.base32;
        await user.save();

        return res.json({
          success: true,
          message:
            "MFA setup is required. Scan the QR code or enter the secret in your authenticator app.",
          data: {
            requiresMFA: true,
            requiresTotpSetup: true,
            sessionToken,
            otpauthUrl: secret.otpauth_url,
            totpSecret: secret.base32,
          },
        });
      }

      const otpauthUrl = speakeasy.otpauthURL({
        secret: user.totpSecret,
        label: `TenantConfig (${user.email})`,
        issuer: "TenantConfig",
        encoding: "base32",
      });

      return res.json({
        success: true,
        message: "MFA is enabled. Enter your authenticator code.",
        data: {
          requiresMFA: true,
          requiresTotp: true,
          sessionToken,
          otpauthUrl,
          totpSecret: user.totpSecret,
        },
      });
    }

    if (
      !authConfig.loginMethods.emailPassword &&
      authConfig.loginMethods.otpLogin
    ) {
      const otp = generateOTP();
      user.otp = otp;
      user.otpExpiry = new Date(Date.now() + 5 * 60 * 1000);
      user.lastActivityAt = new Date();
      await user.save();

      try {
        await sendOTPEmail(user.email, otp);
      } catch (sendErr) {
        return res.status(500).json({
          success: false,
          message: "Unable to deliver OTP email",
        });
      }

      return res.json({
        success: true,
        message: "OTP has been sent to your email.",
        data: {
          requiresMFA: true,
          sessionToken,
        },
      });
    }

    if (
      authConfig.loginMethods.otpLogin &&
      !authConfig.loginMethods.emailPassword
    ) {
      // OTP-only login with no MFA configured.
      const otp = generateOTP();
      user.otp = otp;
      user.otpExpiry = new Date(Date.now() + 5 * 60 * 1000);
      user.lastActivityAt = new Date();
      await user.save();

      try {
        await sendOTPEmail(user.email, otp);
      } catch (sendErr) {
        return res.status(500).json({
          success: false,
          message: "Unable to deliver OTP email",
        });
      }

      return res.json({
        success: true,
        message: "OTP has been sent to your email.",
        data: {
          requiresMFA: true,
          sessionToken,
        },
      });
    }

    user.lastActivityAt = new Date();
    await user.save();

    const token = jwt.sign(
      {
        userId: user._id,
        tenantId: user.tenantId,
        domainId: user.domainId,
        role: "USER",
        authMethods: ["password"],
      },
      process.env.JWT_SECRET,
      {
        expiresIn: `${authConfig.sessionRules.timeoutMinutes}m`,
      },
    );

    return res.json({
      success: true,
      message: `Authentication successful. Session expires after ${authConfig.sessionRules.timeoutMinutes} minute${
        authConfig.sessionRules.timeoutMinutes === 1 ? "" : "s"
      } of inactivity.`,
      data: {
        token,
      },
    });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

router.post("/verify-otp", async (req, res) => {
  try {
    const { email, sessionToken, otp } = req.body;
    if (!email || !sessionToken || !otp) {
      return res.status(400).json({
        success: false,
        message: "email, sessionToken, and otp are required",
      });
    }

    const decoded = jwt.verify(sessionToken, process.env.JWT_SECRET);
    if (decoded.email !== email) {
      return res
        .status(401)
        .json({ success: false, message: "Invalid session" });
    }

    const user = await User.findOne({ email });
    if (!user || user.otp !== otp || user.otpExpiry < new Date()) {
      return res
        .status(401)
        .json({ success: false, message: "Invalid or expired OTP" });
    }

    const authConfig = await resolveAuthConfig(user.tenantId, user.domainId);
    const authToken = jwt.sign(
      {
        userId: user._id,
        tenantId: user.tenantId,
        domainId: user.domainId,
        role: "USER",
        authMethods: ["otp"],
        mfaPassed: true,
      },
      process.env.JWT_SECRET,
      { expiresIn: `${authConfig.sessionRules.timeoutMinutes}m` },
    );

    user.otp = null;
    user.otpExpiry = null;
    user.lastActivityAt = new Date();
    await user.save();

    res.json({
      success: true,
      message: `OTP verification successful. Session expires after ${authConfig.sessionRules.timeoutMinutes} minute${
        authConfig.sessionRules.timeoutMinutes === 1 ? "" : "s"
      } of inactivity.`,
      data: {
        token: authToken,
      },
    });
  } catch (err) {
    res
      .status(401)
      .json({ success: false, message: "Invalid or expired session" });
  }
});

router.post("/verify-totp", async (req, res) => {
  try {
    const { email, sessionToken, totp } = req.body;
    if (!email || !sessionToken || !totp) {
      return res.status(400).json({
        success: false,
        message: "email, sessionToken, and totp are required",
      });
    }

    const decoded = jwt.verify(sessionToken, process.env.JWT_SECRET);
    if (decoded.email !== email) {
      return res
        .status(401)
        .json({ success: false, message: "Invalid session" });
    }

    const user = await User.findOne({ email });
    if (!user || !user.totpSecret) {
      return res.status(401).json({
        success: false,
        message: "User is not enrolled for authenticator MFA.",
      });
    }

    const isValid = speakeasy.totp.verify({
      secret: user.totpSecret,
      encoding: "base32",
      token: totp,
      window: 1,
    });

    if (!isValid) {
      return res
        .status(401)
        .json({ success: false, message: "Invalid authenticator code" });
    }

    const authConfig = await resolveAuthConfig(user.tenantId, user.domainId);
    const authToken = jwt.sign(
      {
        userId: user._id,
        tenantId: user.tenantId,
        domainId: user.domainId,
        role: "USER",
        authMethods: ["totp"],
        mfaPassed: true,
      },
      process.env.JWT_SECRET,
      { expiresIn: `${authConfig.sessionRules.timeoutMinutes}m` },
    );

    user.lastActivityAt = new Date();
    await user.save();

    res.json({
      success: true,
      message: `Authenticator verification successful. Session expires after ${authConfig.sessionRules.timeoutMinutes} minute${
        authConfig.sessionRules.timeoutMinutes === 1 ? "" : "s"
      } of inactivity.`,
      data: {
        token: authToken,
      },
    });
  } catch (err) {
    res
      .status(401)
      .json({ success: false, message: "Invalid or expired session" });
  }
});

router.get("/oauth/google", async (req, res) => {
  try {
    const { tenantId, callbackUrl } = req.query;
    if (!tenantId) {
      return res.status(400).send("tenantId is required");
    }

    if (
      !process.env.GOOGLE_CLIENT_ID ||
      !process.env.GOOGLE_CLIENT_SECRET ||
      !process.env.GOOGLE_OAUTH_REDIRECT_URI
    ) {
      return res
        .status(500)
        .send("Google OAuth is not configured on the server.");
    }

    const tenantObjectId = new mongoose.Types.ObjectId(String(tenantId));
    const authConfig = await resolveAuthConfig(tenantObjectId, null);
    if (!authConfig.loginMethods.googleSSO) {
      return res.status(403).send("SSO is not enabled for this tenant.");
    }

    const authUrl = googleOAuthClient.generateAuthUrl({
      access_type: "offline",
      prompt: "consent",
      scope: ["openid", "email", "profile"],
      state: buildGoogleState({
        tenantId,
        callbackUrl: String(callbackUrl || ""),
      }),
    });

    res.redirect(authUrl);
  } catch (err) {
    res.status(500).send(err.message);
  }
});

router.get("/oauth/google/callback", async (req, res) => {
  try {
    const { code, state } = req.query;
    if (!code || !state) {
      return res
        .status(400)
        .send("Missing code or state from Google callback.");
    }

    const parsed = parseGoogleState(state);
    if (!parsed || !parsed.tenantId) {
      return res.status(400).send("Invalid OAuth state.");
    }

    const { tenantId, callbackUrl } = parsed;
    const { tokens } = await googleOAuthClient.getToken(String(code));
    googleOAuthClient.setCredentials(tokens);

    const ticket = await googleOAuthClient.verifyIdToken({
      idToken: String(tokens.id_token),
      audience: process.env.GOOGLE_CLIENT_ID,
    });
    const payload = ticket.getPayload();
    const email = payload?.email;

    if (!email) {
      return res
        .status(400)
        .send("Unable to determine email from Google account.");
    }

    const tenantObjectId = new mongoose.Types.ObjectId(tenantId);
    const user = await User.findOne({ email, tenantId: tenantObjectId });
    if (!user) {
      return res
        .status(403)
        .send(
          "This Google account is not registered for the requested tenant.",
        );
    }

    const authConfig = await resolveAuthConfig(tenantObjectId, user.domainId);
    const sessionToken = jwt.sign(
      {
        email: user.email,
        tenantId,
        domainId: user.domainId ?? null,
      },
      process.env.JWT_SECRET,
      { expiresIn: "5m" },
    );

    if (authConfig.mfa.enabled) {
      if (!user.totpSecret) {
        const secret = speakeasy.generateSecret({
          name: `TenantConfig (${user.email})`,
        });
        user.totpSecret = secret.base32;
        await user.save();

        const redirect = buildRedirectUrl(
          callbackUrl || `/tenantconfig/auth/${tenantId}`,
          {
            requiresTotpSetup: true,
            sessionToken,
            email: user.email,
            otpauthUrl: secret.otpauth_url,
            callbackUrl,
          },
        );
        return res.redirect(redirect);
      }

      const otpauthUrl = speakeasy.otpauthURL({
        secret: user.totpSecret,
        label: `TenantConfig (${user.email})`,
        issuer: "TenantConfig",
        encoding: "base32",
      });
      const redirect = buildRedirectUrl(
        callbackUrl || `/tenantconfig/auth/${tenantId}`,
        {
          requiresTotp: true,
          sessionToken,
          email: user.email,
          otpauthUrl,
          totpSecret: user.totpSecret,
          callbackUrl,
        },
      );
      return res.redirect(redirect);
    }

    const token = jwt.sign(
      {
        userId: user._id,
        tenantId: user.tenantId,
        domainId: user.domainId,
        role: "USER",
        authMethods: ["sso"],
      },
      process.env.JWT_SECRET,
      {
        expiresIn: `${authConfig.sessionRules.timeoutMinutes}m`,
      },
    );

    const redirect = buildRedirectUrl(
      callbackUrl || `/tenantconfig/auth/${tenantId}`,
      {
        token,
      },
    );
    return res.redirect(redirect);
  } catch (err) {
    res.status(500).send(err.message);
  }
});

export default router;
