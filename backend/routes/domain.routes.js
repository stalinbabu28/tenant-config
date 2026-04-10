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

// 2. CREATE DOMAIN NODE
router.post(
  "/",
  verifyDomainAccess({ targetDomainBodyField: "parentDomainId" }),
  async (req, res) => {
  if (!isSameTenant(req.user.tenantId, req.body.tenantId)) {
    return res.status(403).json({
      success: false,
      message: "Tenant mismatch"
    });
  }

  if (req.body.parentDomainId) {
    if (!isValidObjectId(req.body.parentDomainId)) {
      return res.status(400).json({
        success: false,
        message: "Invalid parentDomainId format"
      });
    }

    const parent = await Domain.findById(req.body.parentDomainId).select("tenantId");

    if (!parent) {
      return res.status(404).json({
        success: false,
        message: "Parent domain not found"
      });
    }

    if (!isSameTenant(parent.tenantId, req.user.tenantId)) {
      return res.status(403).json({
        success: false,
        message: "Parent domain belongs to another tenant"
      });
    }
  } else if (req.user.role === "DOMAIN_ADMIN") {
    return res.status(403).json({
      success: false,
      message: "Domain admins can only create child domains within their assigned subtree"
    });
  }

  const domain = await Domain.create(req.body);

  // Return 201 Created with the hydrated DomainNode object
  res.status(201).json(domain);
});

// 1. FETCH DOMAIN TREE (Flat List)
router.get(
  "/tree/:tenantId",
  verifyDomainAccess({ targetTenantParam: "tenantId" }),
  async (req, res) => {
    if (!isValidObjectId(req.params.tenantId)) {
      return res.status(400).json({
        success: false,
        message: "Invalid tenantId format"
      });
    }

    // Retrieves a flat list of all domains; frontend handles recursive tree building
    // Note: The getDomainTree util was removed in favor of a standard flat query
    let query = { tenantId: req.params.tenantId };
    
    // Maintain RBAC scoping if applicable (assuming domainAccessService handles flat scope fetching if needed)
    if (req.domainAccess?.scope === "domain" && req.domainAccess.rootDomainIds.length > 0) {
        query._id = { $in: req.domainAccess.rootDomainIds }; // Modify based on your exact RBAC logic for flat arrays
    }

    const flatDomains = await Domain.find(query);

    // Returns an array of DomainNode objects
    res.status(200).json(flatDomains);
  }
);

// 3. UPDATE DOMAIN NODE (re-parent)
router.put(
  "/:id",
  verifyDomainAccess({ targetDomainParam: "id" }),
  async (req, res) => {
  if (!isValidObjectId(req.params.id)) {
    return res.status(400).json({
      success: false,
      message: "Invalid domain id format"
    });
  }

  const { parentDomainId } = req.body;

  const existing = await Domain.findById(req.params.id).select("tenantId");

  if (!existing) {
    return res.status(404).json({
      success: false,
      message: "Domain node not found."
    });
  }

  if (!isSameTenant(existing.tenantId, req.user.tenantId)) {
    return res.status(403).json({
      success: false,
      message: "Forbidden"
    });
  }

  if (parentDomainId) {
    if (!isValidObjectId(parentDomainId)) {
      return res.status(400).json({
        success: false,
        message: "Invalid parentDomainId format"
      });
    }

    const parent = await Domain.findById(parentDomainId).select("tenantId");

    if (!parent) {
      return res.status(404).json({
        success: false,
        message: "Domain node not found."
      });
    }

    if (!isSameTenant(parent.tenantId, req.user.tenantId)) {
      return res.status(403).json({
        success: false,
        message: "Parent domain belongs to another tenant"
      });
    }

    if (req.user.role === "DOMAIN_ADMIN") {
      const hasParentAccess = await domainAccessService.isDomainWithinScope({
        tenantId: req.user.tenantId,
        targetDomainId: parentDomainId,
        rootDomainIds: req.domainAccess.rootDomainIds
      });

      if (!hasParentAccess) {
        return res.status(403).json({
          success: false,
          message: "Parent domain is outside your assigned scope"
        });
      }
    }
  } else if (req.user.role === "DOMAIN_ADMIN") {
    return res.status(403).json({
      success: false,
      message: "Domain admins cannot move domains to the tenant root"
    });
  }

  // Upstream traversal cycle check
  if (await isCycle(req.params.id, parentDomainId)) {
    return res.status(409).json({
      success: false,
      message: "Circular dependency detected. Cannot reparent to a child node."
    });
  }

  const updated = await Domain.findByIdAndUpdate(
    req.params.id,
    req.body,
    { new: true }
  );

  res.status(200).json(updated);
});

// 4. DELETE DOMAIN NODE
router.delete(
  "/:id",
  verifyDomainAccess({ targetDomainParam: "id" }),
  async (req, res) => {
    if (!isValidObjectId(req.params.id)) {
      return res.status(400).json({
        success: false,
        message: "Invalid domain id format"
      });
    }

    if (req.user.role === "DOMAIN_ADMIN") {
      return res.status(403).json({
        success: false,
        message: "Domain admins cannot delete domains"
      });
    }

    const existing = await Domain.findById(req.params.id).select("tenantId");

    if (!existing) {
      return res.status(404).json({
        success: false,
        message: "Domain node not found."
      });
    }

    if (!isSameTenant(existing.tenantId, req.user.tenantId)) {
      return res.status(403).json({
        success: false,
        message: "Forbidden"
      });
    }

    const children = await Domain.find({ parentDomainId: req.params.id });

    // Restrict deletion if active child domains exist
    if (children.length > 0) {
      return res.status(409).json({
        success: false,
        message: "Cannot delete a domain that has active child domains."
      });
    }

    await Domain.findByIdAndDelete(req.params.id);

    res.status(200).json({ success: true, message: "Domain successfully deleted." });
  }
);

export default router;
