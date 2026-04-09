import express from "express";
import Domain from "../models/Domain.js";
import { getDomainTree } from "../utils/domainTree.util.js";
import { isCycle } from "../utils/cycleCheck.util.js";
import { verifyDomainAccess } from "../middleware/domainAccess.middleware.js";
import { createDomainAccessService } from "../services/domainAccess.service.js";

const router = express.Router();

const isSameTenant = (a, b) => String(a) === String(b);
const domainAccessService = createDomainAccessService();

// CREATE
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

  res.json({ success: true, data: domain });
});

// GET TREE
router.get(
  "/tree/:tenantId",
  verifyDomainAccess({ targetTenantParam: "tenantId" }),
  async (req, res) => {
    const tree = await getDomainTree(
      req.params.tenantId,
      req.domainAccess?.scope === "domain" ? req.domainAccess.rootDomainIds : []
    );

    res.json({ success: true, data: tree });
  }
);

// UPDATE (re-parent)
router.put(
  "/:id",
  verifyDomainAccess({ targetDomainParam: "id" }),
  async (req, res) => {
  const { parentDomainId } = req.body;

  const existing = await Domain.findById(req.params.id).select("tenantId");

  if (!existing) {
    return res.status(404).json({
      success: false,
      message: "Domain not found"
    });
  }

  if (!isSameTenant(existing.tenantId, req.user.tenantId)) {
    return res.status(403).json({
      success: false,
      message: "Forbidden"
    });
  }

  if (parentDomainId) {
    const parent = await Domain.findById(parentDomainId).select("tenantId");

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

  if (await isCycle(req.params.id, parentDomainId)) {
    return res.status(400).json({
      success: false,
      message: "Cycle detected"
    });
  }

  const updated = await Domain.findByIdAndUpdate(
    req.params.id,
    req.body,
    { new: true }
  );

  res.json({ success: true, data: updated });
});

router.delete(
  "/:id",
  verifyDomainAccess({ targetDomainParam: "id" }),
  async (req, res) => {
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
        message: "Domain not found"
      });
    }

    if (!isSameTenant(existing.tenantId, req.user.tenantId)) {
      return res.status(403).json({
        success: false,
        message: "Forbidden"
      });
    }

    const children = await Domain.find({ parentDomainId: req.params.id });

    if (children.length > 0) {
      return res.status(409).json({
        success: false,
        message: "Cannot delete domain with children"
      });
    }

    await Domain.findByIdAndDelete(req.params.id);

    res.json({ success: true, message: "Deleted" });
  }
);
export default router;
