import { verifyAdminToken } from "../utils/jwt.util.js";

export const requireAuth = (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;

    const token =
      authHeader && authHeader.startsWith("Bearer ")
        ? authHeader.split(" ")[1]
        : null;

    if (!token) {
      return res.status(401).json({
        success: false,
        message: "Unauthorized - No token"
      });
    }

    const decoded = verifyAdminToken(token);

    req.user = decoded;

    next();

  } catch (err) {
    return res.status(401).json({
      success: false,
      message: "Unauthorized - Invalid token"
    });
  }
};