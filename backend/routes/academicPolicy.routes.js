import express from "express";
import mongoose from "mongoose";
import AcademicPolicy from "../models/AcademicPolicy.js";
import Domain from "../models/Domain.js";
import {
  resolveEffectivePolicy,
  getTenantPolicies,
  getDomainPolicy,
  upsertPolicy,
  deletePolicy,
} from "../utils/policyResolution.util.js";
import { createLogger } from "../utils/logger.util.js";

const router = express.Router();
const logger = createLogger("AcademicPolicies");

const isValidObjectId = (value) => mongoose.Types.ObjectId.isValid(value);
const isSameTenant = (left, right) => String(left) === String(right);

// ── GET ALL POLICIES FOR TENANT ────────────────────────────────────────────────
router.get("/:tenantId", async (req, res) => {
  const { tenantId } = req.params;
  const userTenant = req.user?.tenantId;

  logger.info("Fetch tenant policies request", { tenantId });

  try {
    if (!isValidObjectId(tenantId)) {
      return res.status(400).json({
        success: false,
        message: "Invalid tenantId format",
      });
    }

    // Verify tenant access
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

    const policies = await getTenantPolicies(tenantId);

    res.json({
      success: true,
      data: policies,
      count: policies.length,
    });
  } catch (error) {
    logger.error("Fetch policies failed", { tenantId, error: error.message });
    res.status(500).json({
      success: false,
      message: "Failed to fetch policies",
      error: error.message,
    });
  }
});

// ── GET EFFECTIVE POLICY FOR A DOMAIN ──────────────────────────────────────────
router.get("/:tenantId/resolve/:domainId", async (req, res) => {
  const { tenantId, domainId } = req.params;
  const userTenant = req.user?.tenantId;

  logger.info("Resolve effective policy request", { tenantId, domainId });

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

    // Verify domain belongs to tenant
    const domain = await Domain.findOne({
      _id: domainId,
      tenantId,
    }).select("_id domainName");

    if (!domain) {
      return res.status(404).json({
        success: false,
        message: "Domain not found for this tenant",
      });
    }

    const policy = await resolveEffectivePolicy(tenantId, domainId);

    res.json({
      success: true,
      data: {
        policyId: policy._id,
        threshold: policy.threshold,
        policyType: policy.policyType,
        isHardConstraint: policy.isHardConstraint,
        sourceType: policy.domainId ? "domain" : "tenant",
        sourceDomainId: policy.domainId?.toString() || null,
      },
    });
  } catch (error) {
    logger.error("Resolve policy failed", {
      tenantId,
      domainId,
      error: error.message,
    });
    res.status(500).json({
      success: false,
      message: "Failed to resolve policy",
      error: error.message,
    });
  }
});

// ── CREATE OR UPDATE POLICY ────────────────────────────────────────────────────
router.post("/:tenantId", async (req, res) => {
  const { tenantId } = req.params;
  const {
    domainId,
    threshold,
    policyType = "ATTENDANCE",
    isHardConstraint = true,
    actionRestrictions = [],
    description,
  } = req.body;
  const userTenant = req.user?.tenantId;
  const userId = req.user?.id;

  logger.info("Create/update policy request", {
    tenantId,
    domainId,
    threshold,
    userId,
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

    // Validate threshold
    if (typeof threshold !== "number" || threshold < 0 || threshold > 100) {
      return res.status(400).json({
        success: false,
        message: "Threshold must be a number between 0 and 100",
      });
    }

    // If domainId provided, verify it exists
    if (domainId) {
      if (!isValidObjectId(domainId)) {
        return res.status(400).json({
          success: false,
          message: "Invalid domainId format",
        });
      }

      const domain = await Domain.findOne({
        _id: domainId,
        tenantId,
      }).select("_id");

      if (!domain) {
        return res.status(404).json({
          success: false,
          message: "Domain not found for this tenant",
        });
      }
    }

    const policy = await upsertPolicy(tenantId, domainId || null, {
      threshold,
      policyType,
      isHardConstraint,
      actionRestrictions,
      metadata: {
        lastModifiedBy: userId,
        updatedAt: new Date(),
        description,
      },
    });

    logger.info("Policy created/updated successfully", {
      policyId: policy._id,
      tenantId,
      domainId,
      threshold,
    });

    res.status(201).json({
      success: true,
      message: "Policy saved successfully",
      data: policy,
    });
  } catch (error) {
    logger.error("Create/update policy failed", {
      tenantId,
      domainId,
      error: error.message,
    });
    res.status(500).json({
      success: false,
      message: "Failed to save policy",
      error: error.message,
    });
  }
});

// ── DELETE POLICY ──────────────────────────────────────────────────────────────
router.delete("/:tenantId/:policyId", async (req, res) => {
  const { tenantId, policyId } = req.params;
  const userTenant = req.user?.tenantId;

  logger.info("Delete policy request", { tenantId, policyId });

  try {
    if (!isValidObjectId(tenantId) || !isValidObjectId(policyId)) {
      return res.status(400).json({
        success: false,
        message: "Invalid tenantId or policyId format",
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

    // Verify policy belongs to tenant
    const policy = await AcademicPolicy.findOne({
      _id: policyId,
      tenantId,
    });

    if (!policy) {
      return res.status(404).json({
        success: false,
        message: "Policy not found",
      });
    }

    // Prevent deletion of tenant-level policies (only admins can do this via another endpoint)
    if (!policy.domainId) {
      return res.status(400).json({
        success: false,
        message: "Cannot delete tenant-level policies directly",
      });
    }

    await deletePolicy(policyId);

    logger.info("Policy deleted successfully", { policyId, tenantId });

    res.json({
      success: true,
      message: "Policy deleted successfully",
    });
  } catch (error) {
    logger.error("Delete policy failed", {
      tenantId,
      policyId,
      error: error.message,
    });
    res.status(500).json({
      success: false,
      message: "Failed to delete policy",
      error: error.message,
    });
  }
});

export default router;
