import { verifyServiceToken } from "../utils/jwt.util.js";

export const externalAuth = (requiredScope) => {
  return (req, res, next) => {
    try {
      const authHeader = req.headers.authorization;

      if (!authHeader?.startsWith("Bearer ")) {
        return res.status(401).json({
          success: false,
          message: "Missing token",
        });
      }

      const token = authHeader.split(" ")[1];

      const decoded = verifyServiceToken(token);

      // Scope check
      if (!decoded.scope.includes(requiredScope)) {
        return res.status(403).json({
          success: false,
          message: "Insufficient scope",
        });
      }

      req.external = decoded;

      next();
    } catch (err) {
      console.error(err);
      return res.status(401).json({
        success: false,
        message: "Invalid or expired token",
      });
    }
  };
};
