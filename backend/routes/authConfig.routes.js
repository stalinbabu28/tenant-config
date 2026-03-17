import express from "express";
import AuthConfig from "../models/AuthConfig.js";
import mongoose from "mongoose";
const router = express.Router();

// ✅ GET auth config
router.get("/:tenantId", async (req, res) => {
  try {
    const tenantId = new mongoose.Types.ObjectId(req.params.tenantId);

    const config = await AuthConfig.findOne({ tenantId });

    if (!config) {
      return res.json({
        success: true,
        message: "No config found",
        data: null
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

    res.json({
      success: true,
      message: "Auth config fetched",
      data: response
    });

  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});
// ✅ UPDATE (or CREATE if not exists)
router.put("/:tenantId", async (req, res) => {
  try {
    const tenantId = new mongoose.Types.ObjectId(req.params.tenantId);
    const body = req.body;

    // 🔥 Transform Frontend → DB
    const updateData = {
      tenantId,

      loginMethods: {
        emailPassword: body.passwordEnabled,
        googleSSO: body.ssoEnabled,
        otpLogin: body.otpEnabled
      },

      passwordPolicy: {
        minLength: body.passwordPolicy?.minLength,
        requireUppercase: body.passwordPolicy?.requireUppercase,
        requireNumbers: body.passwordPolicy?.requireNumbers,
        requireSpecialChar: body.passwordPolicy?.requireSpecialChars,
        expiryDays: body.passwordPolicy?.expiryDays
      },

      mfa: {
        enabled: body.mfaEnabled,
        methods: body.mfaEnabled ? ["OTP"] : []
      },

      sessionRules: {
        timeoutMinutes: body.sessionTimeoutMinutes,
        maxLoginAttempts: body.maxLoginAttempts,
        lockoutDurationMinutes: body.lockoutDurationMinutes
      }
    };

    const updated = await AuthConfig.findOneAndUpdate(
      { tenantId },
      updateData,
      { new: true, upsert: true }
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

    res.json({
      success: true,
      message: "Authentication configuration updated successfully",
      data: response
    });

  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});


router.post("/validate", async (req, res) => {
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
      lockoutDurationMinutes
    } = payload;

    // 🔐 1. At least one auth method
    if (!passwordEnabled && !ssoEnabled && !otpEnabled) {
      errors.push("At least one authentication method must be enabled.");
    }

    // 🔐 2. MFA dependency
    if (mfaEnabled && !passwordEnabled && !otpEnabled) {
      errors.push("MFA requires either password or OTP to be enabled as a first factor.");
    }

    // 🔐 3. SSO rules
    if (ssoEnabled && (!allowedRoles || allowedRoles.length === 0)) {
      errors.push("SSO is enabled but no roles are assigned to use it.");
    }

    // 🔐 (Optional - future DB validation)
    // if roles don't exist in tenant → skip for now

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
      return res.json({
        success: true,
        message: "Validation failed.",
        data: {
          valid: false,
          errors
        }
      });
    }

    res.json({
      success: true,
      message: "Validation passed.",
      data: {
        valid: true,
        errors: []
      }
    });

  } catch (err) {
    res.status(500).json({
      success: false,
      message: err.message
    });
  }
});

export default router;