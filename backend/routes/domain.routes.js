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
      if (!isSameTenant(req.user.tenantId, tenantId)) {
        logger.warn("Create domain blocked: tenant mismatch", {
          userTenantId: req.user?.tenantId,
          requestTenantId: tenantId,
        });
        return res.status(403).json({
          success: false,
          message: "Tenant mismatch",
        });
      }

      if (req.body.parentDomainId) {
        if (!isValidObjectId(req.body.parentDomainId)) {
          return res.status(400).json({
            success: false,
            message: "Invalid parentDomainId format",
          });
        }

        const parent = await Domain.findById(req.body.parentDomainId).select(
          "tenantId",
        );

        if (!parent) {
          logger.warn("Create domain blocked: parent not found", {
            parentDomainId,
            tenantId,
          });
          return res.status(404).json({
            success: false,
            message: "Parent domain not found",
          });
        }

        if (!isSameTenant(parent.tenantId, req.user.tenantId)) {
          logger.warn(
            "Create domain blocked: parent belongs to another tenant",
            {
              parentDomainId,
              parentTenantId: parent.tenantId,
              userTenantId: req.user?.tenantId,
            },
          );
          return res.status(403).json({
            success: false,
            message: "Parent domain belongs to another tenant",
          });
        }
      } else if (req.user.role === "DOMAIN_ADMIN") {
        logger.warn(
          "Create domain blocked: domain admin attempted root creation",
          {
            userId: req.user?.adminId,
            tenantId,
          },
        );
        return res.status(403).json({
          success: false,
          message:
            "Domain admins can only create child domains within their assigned subtree",
        });
      }

      const domainPayload = {
        tenantId: new mongoose.Types.ObjectId(tenantId),
        domainName: String(domainName).trim(),
        parentDomainId: req.body.parentDomainId
          ? new mongoose.Types.ObjectId(req.body.parentDomainId)
          : null,
      };

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
      res.status(500).json({
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
      const existing = await Domain.findById(domainId).select("tenantId");

      if (!existing) {
        logger.warn("Update domain blocked: domain not found", { domainId });
        return res.status(404).json({
          success: false,
          message: "Domain node not found.",
        });
      }

      if (!isSameTenant(existing.tenantId, req.user.tenantId)) {
        logger.warn("Update domain blocked: tenant mismatch", {
          domainId,
          domainTenantId: existing.tenantId,
          userTenantId: req.user?.tenantId,
        });
        return res.status(403).json({
          success: false,
          message: "Forbidden",
        });
      }

      if (parentDomainId) {
        if (!isValidObjectId(parentDomainId)) {
          return res.status(400).json({
            success: false,
            message: "Invalid parentDomainId format",
          });
        }

        const parent = await Domain.findById(parentDomainId).select("tenantId");

        if (!parent) {
          logger.warn("Update domain blocked: new parent not found", {
            domainId,
            parentDomainId,
          });
          return res.status(404).json({
            success: false,
            message: "Domain node not found.",
          });
        }

        if (!isSameTenant(parent.tenantId, req.user.tenantId)) {
          logger.warn(
            "Update domain blocked: parent belongs to another tenant",
            {
              domainId,
              parentDomainId,
              parentTenantId: parent.tenantId,
              userTenantId: req.user?.tenantId,
            },
          );
          return res.status(403).json({
            success: false,
            message: "Parent domain belongs to another tenant",
          });
        }

        if (req.user.role === "DOMAIN_ADMIN") {
          const hasParentAccess = await domainAccessService.isDomainWithinScope(
            {
              tenantId: req.user.tenantId,
              targetDomainId: parentDomainId,
              rootDomainIds: req.domainAccess.rootDomainIds,
            },
          );

          if (!hasParentAccess) {
            logger.warn("Update domain blocked: parent out of scope", {
              domainId,
              parentDomainId,
              rootDomainIds: req.domainAccess.rootDomainIds,
            });
            return res.status(403).json({
              success: false,
              message: "Parent domain is outside your assigned scope",
            });
          }
        }
      } else if (req.user.role === "DOMAIN_ADMIN") {
        logger.warn(
          "Update domain blocked: domain admin attempted move to root",
          {
            domainId,
            userId: req.user?.adminId,
          },
        );
        return res.status(403).json({
          success: false,
          message: "Domain admins cannot move domains to the tenant root",
        });
      }

      // Upstream traversal cycle check
      if (await isCycle(domainId, parentDomainId)) {
        logger.warn("Update domain blocked: cycle detected", {
          domainId,
          parentDomainId,
        });
        return res.status(409).json({
          success: false,
          message:
            "Circular dependency detected. Cannot reparent to a child node.",
        });
      }

      const updated = await Domain.findByIdAndUpdate(domainId, req.body, {
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
      res.status(500).json({
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
