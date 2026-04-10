import mongoose from "mongoose";

const isSameTenant = (left, right) => String(left) === String(right);
const isValidObjectId = (value) => mongoose.Types.ObjectId.isValid(value);

export const verifyDomainAccess = ({
  domainAccessService = null,
  targetTenantParam,
  targetDomainParam,
  targetDomainBodyField,
  resolveTargetDomain
} = {}) => {
  return async (req, res, next) => {
    try {
      const resolvedDomainAccessService =
        domainAccessService ??
        (await import("../services/domainAccess.service.js")).createDomainAccessService();

      if (!req.user?.tenantId) {
        return res.status(401).json({
          success: false,
          message: "Unauthorized"
        });
      }

      if (
        targetTenantParam &&
        !isSameTenant(req.user.tenantId, req.params[targetTenantParam])
      ) {
        return res.status(403).json({
          success: false,
          message: "Forbidden"
        });
      }

      if (req.user.role === "TENANT_ADMIN") {
        req.domainAccess = {
          scope: "tenant",
          rootDomainIds: []
        };
        return next();
      }

      if (req.user.role !== "DOMAIN_ADMIN" || !req.user.domainAdminId) {
        return res.status(403).json({
          success: false,
          message: "Forbidden"
        });
      }

      const rootDomainIds = await resolvedDomainAccessService.getAdminRootDomainIds({
        tenantId: req.user.tenantId,
        adminId: req.user.domainAdminId
      });

      if (!rootDomainIds.length) {
        return res.status(403).json({
          success: false,
          message: "No assigned domain scope"
        });
      }

      req.domainAccess = {
        scope: "domain",
        rootDomainIds
      };

      let targetDomainId = null;

      if (typeof resolveTargetDomain === "function") {
        targetDomainId = await resolveTargetDomain(req, res, resolvedDomainAccessService);

        if (res.headersSent) {
          return;
        }
      } else if (targetDomainParam) {
        targetDomainId = req.params[targetDomainParam];
      } else if (targetDomainBodyField) {
        targetDomainId = req.body?.[targetDomainBodyField] ?? null;
      }

      if (!targetDomainId) {
        return next();
      }

      if (!isValidObjectId(targetDomainId)) {
        return res.status(400).json({
          success: false,
          message: "Invalid domain id format"
        });
      }

      const hasAccess = await resolvedDomainAccessService.isDomainWithinScope({
        tenantId: req.user.tenantId,
        targetDomainId,
        rootDomainIds
      });

      if (!hasAccess) {
        return res.status(403).json({
          success: false,
          message: "Target resource is outside your assigned domain scope"
        });
      }

      next();
    } catch (error) {
      return res.status(500).json({
        success: false,
        message: error.message
      });
    }
  };
};
