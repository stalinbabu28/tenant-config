import express from "express";
import mongoose from "mongoose";
import AuditLog from "../models/AuditLog.js";
import { createLogger } from "../utils/logger.util.js";

const router = express.Router();
const logger = createLogger("AuditLog");

const isValidObjectId = (value) => mongoose.Types.ObjectId.isValid(value);
const isSameTenant = (left, right) => String(left) === String(right);

// ── GET AUDIT LOGS FOR TENANT ──────────────────────────────────────────────────
router.get("/:tenantId", async (req, res) => {
  const { tenantId } = req.params;
  const { limit = 50, skip = 0, studentId, decision } = req.query;
  const userTenant = req.user?.tenantId;

  logger.info("Fetch audit logs request", {
    tenantId,
    limit,
    skip,
    studentId,
    decision,
  });

  try {
    if (!isValidObjectId(tenantId)) {
      return res.status(400).json({
        success: false,
        message: "Invalid tenantId format",
      });
    }

    if (userTenant && !isSameTenant(userTenant, tenantId)) {
      logger.warn("Forbidden access: Tenant mismatch", {
        tenantId,
        userTenant,
      });
      return res.status(403).json({
        success: false,
        message: "Forbidden - Tenant mismatch",
      });
    }

    // Build query
    const query = { tenantId };

    if (studentId) {
      query.studentId = String(studentId);
    }

    if (decision && ["ALLOWED", "DENIED"].includes(decision)) {
      query.decision = decision;
    }

    // Fetch logs with pagination
    const logs = await AuditLog.find(query)
      .sort({ timestamp: -1 })
      .limit(parseInt(limit))
      .skip(parseInt(skip));

    const total = await AuditLog.countDocuments(query);

    res.json({
      success: true,
      data: logs,
      pagination: {
        total,
        limit: parseInt(limit),
        skip: parseInt(skip),
        hasMore: parseInt(skip) + parseInt(limit) < total,
      },
    });
  } catch (error) {
    logger.error("Fetch audit logs failed", {
      tenantId,
      error: error.message,
    });
    res.status(500).json({
      success: false,
      message: "Failed to fetch audit logs",
      error: error.message,
    });
  }
});

// ── GET AUDIT LOGS FOR STUDENT ────────────────────────────────────────────────
router.get("/:tenantId/student/:studentId", async (req, res) => {
  const { tenantId, studentId } = req.params;
  const { limit = 50, skip = 0 } = req.query;
  const userTenant = req.user?.tenantId;

  logger.info("Fetch student audit logs request", {
    tenantId,
    studentId,
    limit,
    skip,
  });

  try {
    if (!isValidObjectId(tenantId)) {
      return res.status(400).json({
        success: false,
        message: "Invalid tenantId format",
      });
    }

    if (userTenant && !isSameTenant(userTenant, tenantId)) {
      logger.warn("Forbidden access: Tenant mismatch", {
        tenantId,
        userTenant,
      });
      return res.status(403).json({
        success: false,
        message: "Forbidden - Tenant mismatch",
      });
    }

    const logs = await AuditLog.find({
      tenantId,
      studentId: String(studentId),
    })
      .sort({ timestamp: -1 })
      .limit(parseInt(limit))
      .skip(parseInt(skip));

    const total = await AuditLog.countDocuments({
      tenantId,
      studentId: String(studentId),
    });

    res.json({
      success: true,
      data: logs,
      pagination: {
        total,
        limit: parseInt(limit),
        skip: parseInt(skip),
      },
    });
  } catch (error) {
    logger.error("Fetch student audit logs failed", {
      tenantId,
      studentId,
      error: error.message,
    });
    res.status(500).json({
      success: false,
      message: "Failed to fetch student audit logs",
      error: error.message,
    });
  }
});

// ── GET AUDIT LOGS FOR DOMAIN ─────────────────────────────────────────────────
router.get("/:tenantId/domain/:domainId", async (req, res) => {
  const { tenantId, domainId } = req.params;
  const { limit = 50, skip = 0, decision } = req.query;
  const userTenant = req.user?.tenantId;

  logger.info("Fetch domain audit logs request", {
    tenantId,
    domainId,
    limit,
    skip,
    decision,
  });

  try {
    if (!isValidObjectId(tenantId) || !isValidObjectId(domainId)) {
      return res.status(400).json({
        success: false,
        message: "Invalid tenantId or domainId format",
      });
    }

    if (userTenant && !isSameTenant(userTenant, tenantId)) {
      logger.warn("Forbidden access: Tenant mismatch", {
        tenantId,
        userTenant,
      });
      return res.status(403).json({
        success: false,
        message: "Forbidden - Tenant mismatch",
      });
    }

    const query = {
      tenantId,
      domainId,
    };

    if (decision && ["ALLOWED", "DENIED"].includes(decision)) {
      query.decision = decision;
    }

    const logs = await AuditLog.find(query)
      .sort({ timestamp: -1 })
      .limit(parseInt(limit))
      .skip(parseInt(skip));

    const total = await AuditLog.countDocuments(query);

    res.json({
      success: true,
      data: logs,
      pagination: {
        total,
        limit: parseInt(limit),
        skip: parseInt(skip),
      },
    });
  } catch (error) {
    logger.error("Fetch domain audit logs failed", {
      tenantId,
      domainId,
      error: error.message,
    });
    res.status(500).json({
      success: false,
      message: "Failed to fetch domain audit logs",
      error: error.message,
    });
  }
});

// ── GET AUDIT LOG STATISTICS ──────────────────────────────────────────────────
router.get("/:tenantId/stats/summary", async (req, res) => {
  const { tenantId } = req.params;
  const userTenant = req.user?.tenantId;

  logger.info("Fetch audit stats request", { tenantId });

  try {
    if (!isValidObjectId(tenantId)) {
      return res.status(400).json({
        success: false,
        message: "Invalid tenantId format",
      });
    }

    if (userTenant && !isSameTenant(userTenant, tenantId)) {
      logger.warn("Forbidden access: Tenant mismatch", {
        tenantId,
        userTenant,
      });
      return res.status(403).json({
        success: false,
        message: "Forbidden - Tenant mismatch",
      });
    }

    const stats = await AuditLog.aggregate([
      { $match: { tenantId: mongoose.Types.ObjectId(tenantId) } },
      {
        $group: {
          _id: "$decision",
          count: { $sum: 1 },
        },
      },
    ]);

    const totalRequests = await AuditLog.countDocuments({ tenantId });

    const allowed = stats.find((s) => s._id === "ALLOWED")?.count || 0;
    const denied = stats.find((s) => s._id === "DENIED")?.count || 0;

    res.json({
      success: true,
      data: {
        totalRequests,
        allowed,
        denied,
        denialRate:
          totalRequests > 0 ? ((denied / totalRequests) * 100).toFixed(2) : 0,
      },
    });
  } catch (error) {
    logger.error("Fetch audit stats failed", {
      tenantId,
      error: error.message,
    });
    res.status(500).json({
      success: false,
      message: "Failed to fetch audit statistics",
      error: error.message,
    });
  }
});

export default router;
