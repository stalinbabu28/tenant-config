import jwt from "jsonwebtoken";

export const requireAuth = (req, res, next) => {
  try {
    let token;

    // 🔐 1. Check Authorization header (Bearer token)
    const authHeader = req.headers.authorization;

    if (authHeader && authHeader.startsWith("Bearer ")) {
      token = authHeader.split(" ")[1];
    }

    // 🔐 2. Fallback to cookie (optional, keep for flexibility)
    if (!token && req.cookies.jwt) {
      token = req.cookies.jwt;
    }

    if (!token) {
      return res.status(401).json({
        success: false,
        message: "Unauthorized - No token"
      });
    }

    // 🔐 Verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    req.user = decoded;

    next();

  } catch (err) {
    return res.status(401).json({
      success: false,
      message: "Unauthorized - Invalid token"
    });
  }
};