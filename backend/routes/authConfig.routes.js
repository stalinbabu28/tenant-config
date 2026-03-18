import express from "express";
import AuthConfig from "../models/AuthConfig.js";
import mongoose from "mongoose";
const router = express.Router();

// ── Lightweight Structured Logger ──────────────────────────────────────────────
const logger = {
  info: (msg, meta = {}) => {
    const metaStr = Object.keys(meta).length ? JSON.stringify(meta) : "";
    console.log(
      `[${new Date().toISOString()}] [INFO]  [AuthConfig] ${msg} ${metaStr}`,
    );
  },
  warn: (msg, meta = {}) => {
    const metaStr = Object.keys(meta).length ? JSON.stringify(meta) : "";
    console.warn(
      `[${new Date().toISOString()}] [WARN]  [AuthConfig] ${msg} ${metaStr}`,
    );
  },
  error: (msg, meta = {}) => {
    const metaStr = Object.keys(meta).length ? JSON.stringify(meta) : "";
    console.error(
      `[${new Date().toISOString()}] [ERROR] [AuthConfig] ${msg} ${metaStr}`,
    );
  },
};

// ✅ GET auth config
router.get("/:tenantId", async (req, res) => {
  const { tenantId: requestedTenant } = req.params;
  const userTenant = req.user?.tenantId;
  const userId = req.user?.id;

  logger.info("Initiating config fetch", { requestedTenant, userId });

  try {
    const tenantId = new mongoose.Types.ObjectId(requestedTenant);

    if (userTenant !== requestedTenant) {
      logger.warn("Forbidden access attempt: Tenant mismatch", {
        requestedTenant,
        userTenant,
        userId,
      });
      return res.status(403).json({
        success: false,
        message: "Forbidden - Tenant mismatch",
      });
    }

    const config = await AuthConfig.findOne({ tenantId });

    if (!config) {
      logger.info("No config found for tenant", { requestedTenant });
      return res.json({
        success: true,
        message: "No config found",
        data: null,
      });
    }

    // 🔥 Transform DB → Frontend format
    const response = {
      tenantId: config.tenantId.toString(),
      passwordEnabled: config.loginMethods.emailPassword,
      ssoEnabled: config.loginMethods.googleSSO,
      otpEnabled: config.loginMethods.otpLogin,
      mfaEnabled: config.mfa.enabled,
      passwordPolicy: {
        minLength: config.passwordPolicy.minLength,
        requireUppercase: config.passwordPolicy.requireUppercase,
        requireNumbers: config.passwordPolicy.requireNumbers,
        requireSpecialChars: config.passwordPolicy.requireSpecialChar,
        expiryDays: config.passwordPolicy.expiryDays,
      },
      allowedRoles: ["TENANT_ADMIN"], // mock for now
      sessionTimeoutMinutes: config.sessionRules.timeoutMinutes,
      maxLoginAttempts: config.sessionRules.maxLoginAttempts,
      lockoutDurationMinutes: config.sessionRules.lockoutDurationMinutes,
    };

    logger.info("Config fetched successfully", { requestedTenant });
    res.json({
      success: true,
      message: "Auth config fetched",
      data: response,
    });
  } catch (err) {
    logger.error("Failed to fetch config", {
      requestedTenant,
      error: err.message,
    });
    res.status(500).json({ success: false, message: err.message });
  }
});

// ✅ UPDATE (or CREATE if not exists)
router.put("/:tenantId", async (req, res) => {
  const { tenantId: requestedTenant } = req.params;
  const userTenant = req.user?.tenantId;
  const userRole = req.user?.role;
  const userId = req.user?.id;

  logger.info("Initiating config update", { requestedTenant, userId });

  try {
    const tenantId = new mongoose.Types.ObjectId(requestedTenant);

    if (userTenant !== requestedTenant) {
      logger.warn("Forbidden update attempt: Tenant mismatch", {
        requestedTenant,
        userTenant,
        userId,
      });
      return res.status(403).json({
        success: false,
        message: "Forbidden - Tenant mismatch",
      });
    }

    if (userRole !== "TENANT_ADMIN") {
      logger.warn("Forbidden update attempt: Admin access required", {
        requestedTenant,
        userId,
        userRole,
      });
      return res.status(403).json({
        success: false,
        message: "Forbidden - Admin access required",
      });
    }

    const body = req.body;

    // 🔥 Transform Frontend → DB
    const updateData = {
      tenantId,
      loginMethods: {
        emailPassword: body.passwordEnabled,
        googleSSO: body.ssoEnabled,
        otpLogin: body.otpEnabled,
      },
      passwordPolicy: {
        minLength: body.passwordPolicy?.minLength,
        requireUppercase: body.passwordPolicy?.requireUppercase,
        requireNumbers: body.passwordPolicy?.requireNumbers,
        requireSpecialChar: body.passwordPolicy?.requireSpecialChars,
        expiryDays: body.passwordPolicy?.expiryDays,
      },
      mfa: {
        enabled: body.mfaEnabled,
        methods: body.mfaEnabled ? ["OTP"] : [],
      },
      sessionRules: {
        timeoutMinutes: body.sessionTimeoutMinutes,
        maxLoginAttempts: body.maxLoginAttempts,
        lockoutDurationMinutes: body.lockoutDurationMinutes,
      },
    };

    const updated = await AuthConfig.findOneAndUpdate(
      { tenantId },
      updateData,
      { new: true, upsert: true },
    );

    // 🔥 Transform DB → Frontend (IMPORTANT)
    const response = {
      tenantId: updated.tenantId.toString(),
      passwordEnabled: updated.loginMethods.emailPassword,
      ssoEnabled: updated.loginMethods.googleSSO,
      otpEnabled: updated.loginMethods.otpLogin,
      mfaEnabled: updated.mfa.enabled,
      passwordPolicy: {
        minLength: updated.passwordPolicy.minLength,
        requireUppercase: updated.passwordPolicy.requireUppercase,
        requireNumbers: updated.passwordPolicy.requireNumbers,
        requireSpecialChars: updated.passwordPolicy.requireSpecialChar,
        expiryDays: updated.passwordPolicy.expiryDays,
      },
      allowedRoles: ["TENANT_ADMIN"],
      sessionTimeoutMinutes: updated.sessionRules.timeoutMinutes,
      maxLoginAttempts: updated.sessionRules.maxLoginAttempts,
      lockoutDurationMinutes: updated.sessionRules.lockoutDurationMinutes,
    };

    logger.info("Config updated successfully", { requestedTenant });
    res.json({
      success: true,
      message: "Authentication configuration updated successfully",
      data: response,
    });
  } catch (err) {
    logger.error("Failed to update config", {
      requestedTenant,
      error: err.message,
    });
    res.status(500).json({ success: false, message: err.message });
  }
});

// ✅ VALIDATE config
router.post("/validate", async (req, res) => {
  logger.info("Initiating payload validation");

  try {
    const payload = req.body || {};
    const errors = [];

    const {
      passwordEnabled = false,
      ssoEnabled = false,
      otpEnabled = false,
      mfaEnabled = false,
      passwordPolicy = {},
      allowedRoles = [],
      sessionTimeoutMinutes,
      maxLoginAttempts,
      lockoutDurationMinutes,
    } = payload;

    // 🔐 1. At least one auth method
    if (!passwordEnabled && !ssoEnabled && !otpEnabled) {
      errors.push("At least one authentication method must be enabled.");
    }

    // 🔐 2. MFA dependency
    if (mfaEnabled && !passwordEnabled && !otpEnabled) {
      errors.push(
        "MFA requires either password or OTP to be enabled as a first factor.",
      );
    }

    // 🔐 3. SSO rules
    if (ssoEnabled && (!allowedRoles || allowedRoles.length === 0)) {
      errors.push("SSO is enabled but no roles are assigned to use it.");
    }

    // 🔐 4. Password policy
    if (passwordPolicy.minLength !== undefined) {
      if (passwordPolicy.minLength < 4 || passwordPolicy.minLength > 64) {
        errors.push("Password minimum length must be between 4 and 64.");
      }
    }

    if (passwordPolicy.expiryDays !== undefined) {
      if (passwordPolicy.expiryDays < 0 || passwordPolicy.expiryDays > 365) {
        errors.push("Password expiry must be between 0 (never) and 365 days.");
      }
    }

    // 🔐 5. Session timeout
    if (sessionTimeoutMinutes !== undefined) {
      if (sessionTimeoutMinutes < 5 || sessionTimeoutMinutes > 1440) {
        errors.push("Session timeout must be between 5 and 1440 minutes.");
      }
    }

    // 🔐 6. Max login attempts
    if (maxLoginAttempts !== undefined) {
      if (maxLoginAttempts < 1 || maxLoginAttempts > 20) {
        errors.push("Max login attempts must be between 1 and 20.");
      }
    }

    // 🔐 7. Lockout duration
    if (lockoutDurationMinutes !== undefined) {
      if (lockoutDurationMinutes < 1 || lockoutDurationMinutes > 1440) {
        errors.push("Lockout duration must be between 1 and 1440 minutes.");
      }
    }

    // ✅ FINAL RESPONSE
    if (errors.length > 0) {
      logger.warn("Payload validation failed", {
        errorCount: errors.length,
        errors,
      });
      return res.json({
        success: true,
        message: "Validation failed.",
        data: {
          valid: false,
          errors,
        },
      });
    }

    logger.info("Payload validation passed");
    res.json({
      success: true,
      message: "Validation passed.",
      data: {
        valid: true,
        errors: [],
      },
    });
  } catch (err) {
    logger.error("Failed during payload validation", { error: err.message });
    res.status(500).json({
      success: false,
      message: err.message,
    });
  }
});

export default router;
