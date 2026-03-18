import express from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import mongoose from "mongoose";
import Admin from "../models/Admin.js";

const router = express.Router();

// ── Lightweight Structured Logger ──────────────────────────────────────────────
const logger = {
  info: (msg, meta = {}) => {
    const metaStr = Object.keys(meta).length ? JSON.stringify(meta) : "";
    console.log(
      `[${new Date().toISOString()}] [INFO]  [Auth] ${msg} ${metaStr}`,
    );
  },
  warn: (msg, meta = {}) => {
    const metaStr = Object.keys(meta).length ? JSON.stringify(meta) : "";
    console.warn(
      `[${new Date().toISOString()}] [WARN]  [Auth] ${msg} ${metaStr}`,
    );
  },
  error: (msg, meta = {}) => {
    const metaStr = Object.keys(meta).length ? JSON.stringify(meta) : "";
    console.error(
      `[${new Date().toISOString()}] [ERROR] [Auth] ${msg} ${metaStr}`,
    );
  },
};

// ✅ SIGNUP (for testing)
router.post("/signup", async (req, res) => {
  const { email, tenantId, role } = req.body;
  logger.info("Initiating admin signup", { email, tenantId, role });

  try {
    const { name, password } = req.body;
    const hashed = await bcrypt.hash(password, 10);

    const admin = await Admin.create({
      name,
      email,
      passwordHash: hashed,
      tenantId: new mongoose.Types.ObjectId(tenantId),
      role: role || "DOMAIN_ADMIN",
    });

    logger.info("Admin account created successfully", {
      adminId: admin._id,
      email,
      tenantId,
    });
    res.json({
      success: true,
      message: "Admin account created. Please log in.",
    });
  } catch (err) {
    logger.error("Signup failed", { email, error: err.message });
    res.status(500).json({ success: false, message: err.message });
  }
});

// ✅ LOGIN
router.post("/login", async (req, res) => {
  const { email } = req.body;
  logger.info("Login attempt", { email });

  try {
    const { password } = req.body;
    const admin = await Admin.findOne({ email });

    if (!admin) {
      logger.warn("Login failed: User not found", { email });
      return res.json({ success: false, message: "Invalid credentials" });
    }

    const valid = await bcrypt.compare(password, admin.passwordHash);

    if (!valid) {
      logger.warn("Login failed: Invalid password", { email });
      return res.json({ success: false, message: "Invalid credentials" });
    }

    const otp = "123456"; // mock OTP

    admin.otp = otp;
    admin.otpExpiry = new Date(Date.now() + 5 * 60 * 1000);
    await admin.save();

    const sessionToken = jwt.sign({ email }, process.env.JWT_SECRET, {
      expiresIn: "5m",
    });

    logger.info("Password verified, OTP generated", {
      email,
      adminId: admin._id,
    });
    res.json({
      success: true,
      message: "Password verified. OTP sent to registered email.",
      data: {
        requiresMFA: true,
        sessionToken,
      },
    });
  } catch (err) {
    logger.error("Login process failed", { email, error: err.message });
    res.status(500).json({ success: false, message: err.message });
  }
});

// ✅ VERIFY MFA
router.post("/verify-mfa", async (req, res) => {
  const { email } = req.body;
  logger.info("MFA verification attempt", { email });

  try {
    const { otp, sessionToken } = req.body;
    const decoded = jwt.verify(sessionToken, process.env.JWT_SECRET);

    if (decoded.email !== email) {
      logger.warn("MFA failed: Session email mismatch", {
        providedEmail: email,
        tokenEmail: decoded.email,
      });
      return res.json({ success: false, message: "Invalid session" });
    }

    const admin = await Admin.findOne({ email });

    if (!admin || admin.otp !== otp || admin.otpExpiry < new Date()) {
      logger.warn("MFA failed: Invalid or expired OTP", { email });
      return res.json({ success: false, message: "Invalid OTP" });
    }

    const token = jwt.sign(
      {
        adminId: admin._id,
        tenantId: admin.tenantId,
        role: admin.role,
      },
      process.env.JWT_SECRET,
      { expiresIn: "24h" },
    );

    res.cookie("jwt", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production", // Best practice update
      sameSite: "Strict",
    });

    logger.info("MFA verified successfully, session created", {
      email,
      adminId: admin._id,
      tenantId: admin.tenantId,
    });
    res.json({
      success: true,
      message: "MFA verified. Welcome back.",
      data: {
        admin: {
          id: admin._id,
          name: admin.name,
          email: admin.email,
          tenantId: admin.tenantId,
          role: admin.role,
        },
      },
    });
  } catch (err) {
    logger.error("MFA verification failed", { email, error: err.message });
    res.status(500).json({ success: false, message: err.message });
  }
});

// ✅ LOGOUT
router.post("/logout", async (req, res) => {
  logger.info("Logout attempt");

  try {
    res.cookie("jwt", "", {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "Strict",
      maxAge: 0,
    });

    logger.info("Logout successful");
    res.json({
      success: true,
      message: "Logged out.",
    });
  } catch (err) {
    logger.error("Logout failed", { error: err.message });
    res.status(500).json({ success: false, message: err.message });
  }
});

// ✅ RESEND OTP
router.post("/resend-otp", async (req, res) => {
  logger.info("OTP resend requested");

  try {
    const { sessionToken } = req.body;
    const decoded = jwt.verify(sessionToken, process.env.JWT_SECRET);
    const email = decoded.email;

    const admin = await Admin.findOne({ email });

    if (!admin) {
      logger.warn("OTP resend failed: Invalid session or user not found", {
        email,
      });
      return res.json({ success: false, message: "Invalid session" });
    }

    const otp = "123456";

    admin.otp = otp;
    admin.otpExpiry = new Date(Date.now() + 5 * 60 * 1000);
    await admin.save();

    logger.info("OTP resent successfully", { email });
    res.json({
      success: true,
      message: "OTP resent to registered email.",
    });
  } catch (err) {
    logger.error("Failed to resend OTP", { error: err.message });
    res.status(500).json({ success: false, message: err.message });
  }
});

// ✅ GET CURRENT SESSION (ME)
router.get("/me", async (req, res) => {
  logger.info("Validating current session (/me endpoint)");

  try {
    const token = req.cookies.jwt;

    if (!token) {
      logger.warn("Session validation failed: No token provided");
      return res.status(401).json({
        success: false,
        message: "Unauthorized",
      });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const admin = await Admin.findById(decoded.adminId);

    if (!admin) {
      logger.warn("Session validation failed: Admin not found", {
        adminId: decoded.adminId,
      });
      return res.status(401).json({
        success: false,
        message: "Invalid session",
      });
    }

    logger.info("Session is valid", { adminId: admin._id, email: admin.email });
    res.json({
      success: true,
      message: "Session valid.",
      data: {
        admin: {
          id: admin._id,
          name: admin.name,
          email: admin.email,
          tenantId: admin.tenantId,
          role: admin.role,
        },
      },
    });
  } catch (err) {
    logger.warn("Session expired or invalid token", { error: err.message });
    res.status(401).json({
      success: false,
      message: "Session expired",
    });
  }
});

export default router;
