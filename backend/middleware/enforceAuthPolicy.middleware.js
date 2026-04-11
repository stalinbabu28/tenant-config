import { resolveAuthConfig } from "../utils/authConfig.util.js";

export const enforceAuthPolicy = async (req, res, next) => {
  try {
    if (!req.user?.tenantId) {
      return res.status(401).json({
        success: false,
        message: "Unauthorized"
      });
    }

    const authConfig = await resolveAuthConfig(req.user.tenantId, req.user.domainId ?? null);

    if (authConfig.mfa?.enabled && req.user.authLevel !== "MFA") {
      return res.status(403).json({
        success: false,
        message: "MFA is required for this tenant"
      });
    }

    if (
      Array.isArray(authConfig.allowedRoles) &&
      authConfig.allowedRoles.length > 0 &&
      !authConfig.allowedRoles.includes(req.user.role)
    ) {
      return res.status(403).json({
        success: false,
        message: "Role is not allowed by tenant policy"
      });
    }

    req.authConfig = authConfig;
    next();
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: error.message
    });
  }
};
