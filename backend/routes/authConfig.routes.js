import express from "express";
import AuthConfig from "../models/AuthConfig.js";
import DomainAuthConfig from "../models/DomainAuthConfig.js";
import Domain from "../models/Domain.js";
import mongoose from "mongoose";
import { mapAuthConfig, resolveAuthConfigWithSource } from "../utils/authConfig.util.js";
const router = express.Router();

const isValidObjectId = (value) => mongoose.Types.ObjectId.isValid(value);
const isSameTenant = (left, right) => String(left) === String(right);

const toObjectId = (value) => new mongoose.Types.ObjectId(value);

const buildConfigUpdateData = (tenantId, domainId, body) => ({
  tenantId,
  ...(domainId ? { domainId } : { domainId: null }),
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
});

const resolveScopedDomainId = async ({ requestedTenant, rawDomainId }) => {
  if (!rawDomainId) {
    return null;
  }

  if (!isValidObjectId(rawDomainId)) {
    throw new Error("INVALID_DOMAIN_ID");
  }

  const domain = await Domain.findOne({
    _id: toObjectId(rawDomainId),
    tenantId: toObjectId(requestedTenant),
  }).select("_id tenantId");

  if (!domain) {
    throw new Error("DOMAIN_NOT_FOUND");
  }

  return domain._id;
};

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

// Get auth config (auto-create if missing)
router.get("/:tenantId", async (req, res) => {
  const { tenantId: requestedTenant } = req.params;
  const userTenant = req.user?.tenantId;
  const userId = req.user?.id;
  const rawDomainId = req.query.domainId ?? null;

  logger.info("Initiating config fetch", { requestedTenant, userId });

  try {
    if (!isValidObjectId(requestedTenant)) {
      return res.status(400).json({
        success: false,
        message: "Invalid tenantId format",
      });
    }

    const tenantId = toObjectId(requestedTenant);

    if (userTenant && !isSameTenant(userTenant, requestedTenant)) {
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

    let domainId = null;

    try {
      domainId = await resolveScopedDomainId({
        requestedTenant,
        rawDomainId,
      });
    } catch (scopeError) {
      if (scopeError.message === "INVALID_DOMAIN_ID") {
        return res.status(400).json({
          success: false,
          message: "Invalid domainId format",
        });
      }

      if (scopeError.message === "DOMAIN_NOT_FOUND") {
        return res.status(404).json({
          success: false,
          message: "Domain not found for this tenant",
        });
      }

      throw scopeError;
    }

    const resolved = await resolveAuthConfigWithSource(tenantId, domainId);
    const response = {
      ...mapAuthConfig(resolved.config, {
        sourceType: resolved.sourceType,
        sourceDomainId: resolved.sourceDomainId,
      }),
      requestedDomainId: domainId?.toString() ?? null,
      allowedRoles: ["TENANT_ADMIN", "DOMAIN_ADMIN"],
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

// Update config (create if missing)
router.put("/:tenantId", async (req, res) => {
  const { tenantId: requestedTenant } = req.params;
  const userTenant = req.user?.tenantId;
  const userRole = req.user?.role;
  const userId = req.user?.id;
  const rawDomainId = req.query.domainId ?? req.body?.domainId ?? null;

  logger.info("Initiating config update", { requestedTenant, userId });

  try {
    if (!isValidObjectId(requestedTenant)) {
      return res.status(400).json({
        success: false,
        message: "Invalid tenantId format",
      });
    }

    const tenantId = toObjectId(requestedTenant);

    if (!isSameTenant(userTenant, requestedTenant)) {
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

    if (userRole !== "TENANT_ADMIN" && userRole !== "DOMAIN_ADMIN") {
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
    let domainId = null;

    try {
      domainId = await resolveScopedDomainId({
        requestedTenant,
        rawDomainId,
      });
    } catch (scopeError) {
      if (scopeError.message === "INVALID_DOMAIN_ID") {
        return res.status(400).json({
          success: false,
          message: "Invalid domainId format",
        });
      }

      if (scopeError.message === "DOMAIN_NOT_FOUND") {
        return res.status(404).json({
          success: false,
          message: "Domain not found for this tenant",
        });
      }

      throw scopeError;
    }

    const updateData = buildConfigUpdateData(tenantId, domainId, body);

    const updated = domainId
      ? await DomainAuthConfig.findOneAndUpdate(
          { tenantId, domainId },
          updateData,
          { new: true, upsert: true, setDefaultsOnInsert: true },
        )
      : await AuthConfig.findOneAndUpdate(
          { tenantId, domainId: null },
          updateData,
          { new: true, upsert: true, setDefaultsOnInsert: true },
        );

    const response = {
      ...mapAuthConfig(updated, {
        sourceType: domainId ? "domain" : "tenant",
        sourceDomainId: domainId,
      }),
      requestedDomainId: domainId?.toString() ?? null,
      allowedRoles: ["TENANT_ADMIN"],
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

// Cascade a domain auth config to descendants that do not have explicit overrides
router.post("/:tenantId/cascade", async (req, res) => {
  const { tenantId: requestedTenant } = req.params;
  const { domainId: rawDomainId } = req.body || {};
  const userTenant = req.user?.tenantId;
  const userRole = req.user?.role;
  const userId = req.user?.id;

  logger.info("Initiating domain auth config cascade", {
    requestedTenant,
    rawDomainId,
    userId,
  });

  try {
    if (!isValidObjectId(requestedTenant)) {
      return res.status(400).json({
        success: false,
        message: "Invalid tenantId format",
      });
    }

    if (!isSameTenant(userTenant, requestedTenant)) {
      return res.status(403).json({
        success: false,
        message: "Forbidden - Tenant mismatch",
      });
    }

    if (userRole !== "TENANT_ADMIN" && userRole !== "DOMAIN_ADMIN") {
      return res.status(403).json({
        success: false,
        message: "Forbidden - Admin access required",
      });
    }

    if (!rawDomainId) {
      return res.status(400).json({
        success: false,
        message: "domainId is required",
      });
    }

    let sourceDomainId = null;
    try {
      sourceDomainId = await resolveScopedDomainId({
        requestedTenant,
        rawDomainId,
      });
    } catch (scopeError) {
      if (scopeError.message === "INVALID_DOMAIN_ID") {
        return res.status(400).json({
          success: false,
          message: "Invalid domainId format",
        });
      }

      if (scopeError.message === "DOMAIN_NOT_FOUND") {
        return res.status(404).json({
          success: false,
          message: "Domain not found for this tenant",
        });
      }

      throw scopeError;
    }

    const tenantId = toObjectId(requestedTenant);

    const sourceConfig = await DomainAuthConfig.findOne({
      tenantId,
      domainId: sourceDomainId,
    });

    if (!sourceConfig) {
      return res.status(400).json({
        success: false,
        message:
          "No explicit domain auth config found on the selected domain. Save a domain-specific config first.",
      });
    }

    const descendantsAggregation = await Domain.aggregate([
      {
        $match: {
          _id: sourceDomainId,
          tenantId,
        },
      },
      {
        $graphLookup: {
          from: "domains",
          startWith: "$_id",
          connectFromField: "_id",
          connectToField: "parentDomainId",
          restrictSearchWithMatch: { tenantId },
          as: "descendants",
        },
      },
      {
        $project: {
          _id: 0,
          descendantIds: "$descendants._id",
        },
      },
    ]);

    const descendantIds = (descendantsAggregation[0]?.descendantIds || []).filter(
      (id) => String(id) !== String(sourceDomainId),
    );

    if (!descendantIds.length) {
      return res.json({
        success: true,
        message: "No child domains found to cascade config.",
        data: {
          sourceDomainId: sourceDomainId.toString(),
          scannedChildren: 0,
          skippedExisting: 0,
          cascaded: 0,
        },
      });
    }

    const existingChildConfigs = await DomainAuthConfig.find({
      tenantId,
      domainId: { $in: descendantIds },
    }).select("domainId");

    const existingDomainSet = new Set(
      existingChildConfigs.map((config) => String(config.domainId)),
    );

    const cascadeTargets = descendantIds.filter(
      (id) => !existingDomainSet.has(String(id)),
    );

    const sourceObject = sourceConfig.toObject();
    const cascadePayloadBase = {
      loginMethods: sourceObject.loginMethods,
      passwordPolicy: sourceObject.passwordPolicy,
      mfa: sourceObject.mfa,
      sessionRules: sourceObject.sessionRules,
    };

    if (cascadeTargets.length) {
      await DomainAuthConfig.insertMany(
        cascadeTargets.map((childDomainId) => ({
          tenantId,
          domainId: childDomainId,
          ...cascadePayloadBase,
        })),
        { ordered: false },
      );
    }

    return res.json({
      success: true,
      message: "Domain auth config cascade completed.",
      data: {
        sourceDomainId: sourceDomainId.toString(),
        scannedChildren: descendantIds.length,
        skippedExisting: existingDomainSet.size,
        cascaded: cascadeTargets.length,
      },
    });
  } catch (err) {
    logger.error("Failed to cascade domain auth config", {
      requestedTenant,
      rawDomainId,
      error: err.message,
    });
    return res.status(500).json({
      success: false,
      message: err.message,
    });
  }
});

// Validate config payload
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

    // 1) At least one auth method
    if (!passwordEnabled && !ssoEnabled && !otpEnabled) {
      errors.push("At least one authentication method must be enabled.");
    }

    // 2) MFA dependency
    if (mfaEnabled && !passwordEnabled && !otpEnabled) {
      errors.push(
        "MFA requires either password or OTP to be enabled as a first factor.",
      );
    }

    // 3) SSO rules
    if (ssoEnabled && (!allowedRoles || allowedRoles.length === 0)) {
      errors.push("SSO is enabled but no roles are assigned to use it.");
    }

    // 4) Password policy
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

    // 5) Session timeout
    if (sessionTimeoutMinutes !== undefined) {
      if (sessionTimeoutMinutes < 5 || sessionTimeoutMinutes > 1440) {
        errors.push("Session timeout must be between 5 and 1440 minutes.");
      }
    }

    // 6) Max login attempts
    if (maxLoginAttempts !== undefined) {
      if (maxLoginAttempts < 1 || maxLoginAttempts > 20) {
        errors.push("Max login attempts must be between 1 and 20.");
      }
    }

    // 7) Lockout duration
    if (lockoutDurationMinutes !== undefined) {
      if (lockoutDurationMinutes < 1 || lockoutDurationMinutes > 1440) {
        errors.push("Lockout duration must be between 1 and 1440 minutes.");
      }
    }

    // Final response
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
