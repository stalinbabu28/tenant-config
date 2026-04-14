import express from "express";
import mongoose from "mongoose";
import Domain from "../models/Domain.js";
import { isCycle } from "../utils/cycleCheck.util.js";
import { verifyDomainAccess } from "../middleware/domainAccess.middleware.js";
import { createDomainAccessService } from "../services/domainAccess.service.js";

const router = express.Router();

const isSameTenant = (a, b) => String(a) === String(b);
const isValidObjectId = (value) => mongoose.Types.ObjectId.isValid(value);
const domainAccessService = createDomainAccessService();

// ── Lightweight Structured Logger ──────────────────────────────────────────────
const logger = {
  info: (msg, meta = {}) => {
    const metaStr = Object.keys(meta).length ? JSON.stringify(meta) : "";
    console.log(
      `[${new Date().toISOString()}] [INFO]  [Domain] ${msg} ${metaStr}`,
    );
  },
  warn: (msg, meta = {}) => {
    const metaStr = Object.keys(meta).length ? JSON.stringify(meta) : "";
    console.warn(
      `[${new Date().toISOString()}] [WARN]  [Domain] ${msg} ${metaStr}`,
    );
  },
  error: (msg, meta = {}) => {
    const metaStr = Object.keys(meta).length ? JSON.stringify(meta) : "";
    console.error(
      `[${new Date().toISOString()}] [ERROR] [Domain] ${msg} ${metaStr}`,
    );
  },
};

const apiError = (status, message) => {
  const error = new Error(message);
  error.status = status;
  return error;
};

const validateParentDomain = async ({
  parentDomainId,
  user,
  rootDomainIds,
  notFoundMessage,
  denialMessage,
}) => {
  if (!isValidObjectId(parentDomainId)) {
    throw apiError(400, "Invalid parentDomainId format");
  }

  const parent = await Domain.findById(parentDomainId).select("tenantId");
  if (!parent) {
    throw apiError(404, notFoundMessage);
  }

  if (!isSameTenant(parent.tenantId, user.tenantId)) {
    throw apiError(403, "Parent domain belongs to another tenant");
  }

  if (user.role === "DOMAIN_ADMIN") {
    const hasParentAccess = await domainAccessService.isDomainWithinScope({
      tenantId: user.tenantId,
      targetDomainId: parentDomainId,
      rootDomainIds,
    });

    if (!hasParentAccess) {
      throw apiError(403, denialMessage);
    }
  }

  return parent;
};

const buildCreateDomainPayload = async ({
  tenantId,
  domainName,
  parentDomainId,
  user,
  rootDomainIds,
}) => {
  if (!isSameTenant(user.tenantId, tenantId)) {
    throw apiError(403, "Tenant mismatch");
  }

  if (parentDomainId) {
    await validateParentDomain({
      parentDomainId,
      user,
      rootDomainIds,
      notFoundMessage: "Parent domain not found",
      denialMessage: "Parent domain is outside your assigned scope",
    });
  } else if (user.role === "DOMAIN_ADMIN") {
    throw apiError(
      403,
      "Domain admins can only create child domains within their assigned subtree",
    );
  }

  return {
    tenantId: new mongoose.Types.ObjectId(tenantId),
    domainName: String(domainName).trim(),
    parentDomainId: parentDomainId
      ? new mongoose.Types.ObjectId(parentDomainId)
      : null,
  };
};

const buildUpdateDomainPayload = async ({
  domainId,
  body,
  user,
  rootDomainIds,
}) => {
  const existing = await Domain.findById(domainId).select("tenantId");

  if (!existing) {
    throw apiError(404, "Domain node not found.");
  }

  if (!isSameTenant(existing.tenantId, user.tenantId)) {
    throw apiError(403, "Forbidden");
  }

  const parentDomainId = body.parentDomainId;
  if (parentDomainId) {
    await validateParentDomain({
      parentDomainId,
      user,
      rootDomainIds,
      notFoundMessage: "Domain node not found.",
      denialMessage: "Parent domain is outside your assigned scope",
    });
  } else if (user.role === "DOMAIN_ADMIN") {
    throw apiError(403, "Domain admins cannot move domains to the tenant root");
  }

  if (await isCycle(domainId, parentDomainId)) {
    throw apiError(
      409,
      "Circular dependency detected. Cannot reparent to a child node.",
    );
  }

  const updatePayload = {};
  if (typeof body.domainName === "string" && body.domainName.trim()) {
    updatePayload.domainName = body.domainName.trim();
  }

  if (body.parentDomainId !== undefined) {
    updatePayload.parentDomainId = body.parentDomainId
      ? new mongoose.Types.ObjectId(body.parentDomainId)
      : null;
  }

  if (!Object.keys(updatePayload).length) {
    throw apiError(400, "No valid fields were provided for update.");
  }

  return updatePayload;
};

// 2. CREATE DOMAIN NODE
router.post(
  "/",
  verifyDomainAccess({ targetDomainBodyField: "parentDomainId" }),
  async (req, res) => {
    const { tenantId, parentDomainId, domainName } = req.body;

    logger.info("Create domain request received", {
      userId: req.user?.adminId,
      role: req.user?.role,
      tenantId,
      parentDomainId,
      domainName,
    });

    try {
      const domainPayload = await buildCreateDomainPayload({
        tenantId,
        domainName,
        parentDomainId: req.body.parentDomainId,
        user: req.user,
        rootDomainIds: req.domainAccess.rootDomainIds,
      });

      const domain = await Domain.create(domainPayload);

      logger.info("Domain created successfully", {
        domainId: domain._id,
        tenantId: domain.tenantId,
      });

      // Return 201 Created with the hydrated DomainNode object
      res.status(201).json(domain);
    } catch (error) {
      logger.error("Create domain failed", {
        tenantId,
        parentDomainId,
        error: error.message,
      });
      res.status(error.status || 500).json({
        success: false,
        message: error.message,
      });
    }
  },
);

// 1. FETCH DOMAIN TREE (Flat List)
router.get(
  "/tree/:tenantId",
  verifyDomainAccess({ targetTenantParam: "tenantId" }),
  async (req, res) => {
    if (!isValidObjectId(req.params.tenantId)) {
      return res.status(400).json({
        success: false,
        message: "Invalid tenantId format",
      });
    }

    const { tenantId } = req.params;

    logger.info("Fetch domain tree request received", {
      tenantId,
      userId: req.user?.adminId,
      role: req.user?.role,
      scope: req.domainAccess?.scope,
    });

    try {
      // Retrieves a flat list of all domains; frontend handles recursive tree building
      // Note: The getDomainTree util was removed in favor of a standard flat query
      let query = { tenantId };

      // For DOMAIN_ADMIN users, include assigned roots and all descendant domains.
      if (
        req.domainAccess?.scope === "domain" &&
        req.domainAccess.rootDomainIds.length > 0
      ) {
        const accessibleDomainIds =
          await domainAccessService.listAccessibleDomainIds({
            tenantId,
            rootDomainIds: req.domainAccess.rootDomainIds,
          });

        query._id = { $in: accessibleDomainIds };
      }

      const flatDomains = await Domain.find(query);

      logger.info("Domain tree fetched successfully", {
        tenantId,
        count: flatDomains.length,
      });

      // Returns an array of DomainNode objects
      res.status(200).json(flatDomains);
    } catch (error) {
      logger.error("Fetch domain tree failed", {
        tenantId,
        error: error.message,
      });
      res.status(500).json({
        success: false,
        message: error.message,
      });
    }
  },
);

// 3. UPDATE DOMAIN NODE (re-parent)
router.put(
  "/:id",
  verifyDomainAccess({ targetDomainParam: "id" }),
  async (req, res) => {
    if (!isValidObjectId(req.params.id)) {
      return res.status(400).json({
        success: false,
        message: "Invalid domain id format",
      });
    }

    const { parentDomainId } = req.body;
    const domainId = req.params.id;

    logger.info("Update domain request received", {
      domainId,
      parentDomainId,
      userId: req.user?.adminId,
      role: req.user?.role,
    });

    try {
      const updatePayload = await buildUpdateDomainPayload({
        domainId,
        body: req.body,
        user: req.user,
        rootDomainIds: req.domainAccess.rootDomainIds,
      });

      const updated = await Domain.findByIdAndUpdate(domainId, updatePayload, {
        new: true,
      });

      logger.info("Domain updated successfully", {
        domainId,
        tenantId: updated?.tenantId,
      });

      res.status(200).json(updated);
    } catch (error) {
      logger.error("Update domain failed", {
        domainId,
        parentDomainId,
        error: error.message,
      });
      res.status(error.status || 500).json({
        success: false,
        message: error.message,
      });
    }
  },
);

// 4. DELETE DOMAIN NODE
router.delete(
  "/:id",
  verifyDomainAccess({ targetDomainParam: "id" }),
  async (req, res) => {
    if (!isValidObjectId(req.params.id)) {
      return res.status(400).json({
        success: false,
        message: "Invalid domain id format",
      });
    }

    const domainId = req.params.id;

    logger.info("Delete domain request received", {
      domainId,
      userId: req.user?.adminId,
      role: req.user?.role,
    });

    try {
      if (req.user.role === "DOMAIN_ADMIN") {
        logger.warn("Delete domain blocked: domain admin not allowed", {
          domainId,
          userId: req.user?.adminId,
        });
        return res.status(403).json({
          success: false,
          message: "Domain admins cannot delete domains",
        });
      }

      const existing = await Domain.findById(domainId).select("tenantId");

      if (!existing) {
        logger.warn("Delete domain blocked: domain not found", { domainId });
        return res.status(404).json({
          success: false,
          message: "Domain node not found.",
        });
      }

      if (!isSameTenant(existing.tenantId, req.user.tenantId)) {
        logger.warn("Delete domain blocked: tenant mismatch", {
          domainId,
          domainTenantId: existing.tenantId,
          userTenantId: req.user?.tenantId,
        });
        return res.status(403).json({
          success: false,
          message: "Forbidden",
        });
      }

      const children = await Domain.find({ parentDomainId: domainId });

      // Restrict deletion if active child domains exist
      if (children.length > 0) {
        logger.warn("Delete domain blocked: domain has active children", {
          domainId,
          childCount: children.length,
        });
        return res.status(409).json({
          success: false,
          message: "Cannot delete a domain that has active child domains.",
        });
      }

      await Domain.findByIdAndDelete(domainId);

      logger.info("Domain deleted successfully", { domainId });
      res
        .status(200)
        .json({ success: true, message: "Domain successfully deleted." });
    } catch (error) {
      logger.error("Delete domain failed", {
        domainId,
        error: error.message,
      });
      res.status(500).json({
        success: false,
        message: error.message,
      });
    }
  },
);

export default router;
