import express from "express";
import bcrypt from "bcrypt";
import mongoose from "mongoose";
import nodemailer from "nodemailer";
import crypto from "crypto";
import Admin from "../models/Admin.js";
import { resolveAuthConfig } from "../utils/authConfig.util.js";
import { requireAuth } from "../middleware/auth.middleware.js";
import { enforceAuthPolicy } from "../middleware/enforceAuthPolicy.middleware.js";
import {
  issueAdminMfaSessionToken,
  issueAdminToken,
  verifyAdminMfaSessionToken,
} from "../utils/jwt.util.js";
import dotenv from "dotenv";
dotenv.config();
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

// ── Email Setup & Helpers ──────────────────────────────────────────────
const transporter = nodemailer.createTransport({
  secure: true,
  host: "smtp.gmail.com",
  port: 465,
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

// Generate a secure, random 6-digit OTP
const generateOTP = () => crypto.randomInt(100000, 999999).toString();
const isLockedOut = (entity) =>
  !!entity.lockoutUntil && entity.lockoutUntil > new Date();

const lockoutRemainingMinutes = (entity) => {
  if (!entity.lockoutUntil) return 0;
  return Math.ceil((entity.lockoutUntil - new Date()) / 60000);
};

// Function to send the email
const sendOTPEmail = async (email, otp) => {
  try {
    const htmlTemplate = `
    <!DOCTYPE html>
    <html>
      <body style="margin:0; padding:0; background-color:#0f172a; font-family:Arial, sans-serif; color:#e5e7eb;">
        
        <table align="center" width="100%" cellpadding="0" cellspacing="0" style="padding:40px 0;">
          <tr>
            <td align="center">
              
              <table width="420" cellpadding="0" cellspacing="0" style="background-color:#111827; border-radius:12px; padding:30px; box-shadow:0 10px 25px rgba(0,0,0,0.5);">
                
                <tr>
                  <td style="text-align:center; padding-bottom:20px;">
                    <h2 style="margin:0; color:#f9fafb; font-weight:600;">
                      Verification Code
                    </h2>
                    <p style="margin:8px 0 0; font-size:14px; color:#9ca3af;">
                      Use the code below to continue
                    </p>
                  </td>
                </tr>

                <tr>
                  <td style="text-align:center; padding:20px 0;">
                    <div style="display:inline-block; background:#1f2937; padding:16px 28px; border-radius:8px; letter-spacing:6px; font-size:28px; font-weight:bold; color:#38bdf8;">
                      ${otp}
                    </div>
                  </td>
                </tr>

                <tr>
                  <td style="text-align:center; font-size:14px; color:#9ca3af; padding-bottom:20px;">
                    This code will expire in <span style="color:#fbbf24;">5 minutes</span>.
                  </td>
                </tr>

                <tr>
                  <td style="text-align:center; font-size:13px; color:#6b7280;">
                    Do not share this code with anyone for security reasons.
                  </td>
                </tr>

                <tr>
                  <td style="padding:20px 0;">
                    <hr style="border:none; border-top:1px solid #1f2937;">
                  </td>
                </tr>

                <tr>
                  <td style="text-align:center; font-size:12px; color:#6b7280;">
                    If you didn’t request this, you can safely ignore this email.
                  </td>
                </tr>

              </table>

            </td>
          </tr>
        </table>

      </body>
    </html>
    `;

    await transporter.sendMail({
      to: email,
      subject: "Your MFA Login Code",
      text: `Your verification code is: ${otp}\n\nThis code will expire in 5 minutes. Do not share this code with anyone.`,
      html: htmlTemplate,
    });

    logger.info("OTP Email sent successfully", { email });
  } catch (error) {
    logger.error("Failed to send OTP email", { email, error: error.message });
    throw new Error("Failed to send email");
  }
};

// Signup (for testing)
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

// Login
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

    if (isLockedOut(admin)) {
      const minutes = lockoutRemainingMinutes(admin);
      logger.warn("Login blocked: account locked", { email, minutes });
      return res.status(403).json({
        success: false,
        message: `Account locked. Try again in ${minutes} minute${
          minutes === 1 ? "" : "s"
        }.`,
      });
    }

    const authConfig = await resolveAuthConfig(admin.tenantId, admin.domainId ?? null);

    if (
      Array.isArray(authConfig.allowedRoles) &&
      authConfig.allowedRoles.length > 0 &&
      !authConfig.allowedRoles.includes(admin.role)
    ) {
      logger.warn("Login blocked: role restricted by policy", {
        email,
        role: admin.role,
      });
      return res.status(403).json({
        success: false,
        message: "This role is not allowed by tenant policy",
      });
    }

    if (!authConfig.loginMethods.emailPassword && !authConfig.loginMethods.otpLogin) {
      return res.status(403).json({
        success: false,
        message: "No supported login method is enabled for this tenant",
      });
    }

    if (authConfig.loginMethods.emailPassword) {
      if (!password) {
        return res.status(400).json({
          success: false,
          message: "Password is required for this tenant configuration",
        });
      }

      const valid = await bcrypt.compare(password, admin.passwordHash);
      if (!valid) {
        admin.failedLoginAttempts += 1;
        if (
          authConfig.sessionRules.maxLoginAttempts > 0 &&
          admin.failedLoginAttempts >= authConfig.sessionRules.maxLoginAttempts
        ) {
          admin.lockoutUntil = new Date(
            Date.now() + authConfig.sessionRules.lockoutDurationMinutes * 60000,
          );
        }

        await admin.save();
        logger.warn("Login failed: Invalid password", { email });
        return res.status(401).json({ success: false, message: "Invalid credentials" });
      }
    }

    admin.failedLoginAttempts = 0;
    admin.lockoutUntil = null;

    if (authConfig.mfa.enabled || authConfig.loginMethods.otpLogin) {
      const otp = generateOTP();

      admin.otp = otp;
      admin.otpExpiry = new Date(Date.now() + 5 * 60 * 1000);
      await admin.save();

      await sendOTPEmail(email, otp);
      const sessionToken = issueAdminMfaSessionToken({
        adminId: admin._id.toString(),
        email,
        tenantId: admin.tenantId.toString(),
      });

      logger.info("Password verified, OTP generated", {
        email,
        adminId: admin._id,
      });
      return res.json({
        success: true,
        message: "Password verified. OTP sent to registered email.",
        data: {
          requiresMFA: true,
          sessionToken,
        },
      });
    }

    admin.lastActivityAt = new Date();
    await admin.save();

    const token = issueAdminToken({
      adminId: admin._id.toString(),
      tenantId: admin.tenantId.toString(),
      role: admin.role,
      authLevel: "PASSWORD",
      domainAdminId: admin.role === "DOMAIN_ADMIN" ? admin._id.toString() : null,
      expiresIn: `${authConfig.sessionRules.timeoutMinutes}m`,
    });

    res.cookie("jwt", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "Strict",
    });

    return res.json({
      success: true,
      message: "Authentication successful.",
      data: {
        token,
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
    logger.error("Login process failed", { email, error: err.message });
    res.status(500).json({ success: false, message: err.message });
  }
});

// Verify MFA
router.post("/verify-mfa", async (req, res) => {
  const { email } = req.body;
  logger.info("MFA verification attempt", { email });

  try {
    const { otp, sessionToken } = req.body;
    const decoded = verifyAdminMfaSessionToken(sessionToken);

    if (decoded.email !== email) {
      logger.warn("MFA failed: Session email mismatch", {
        providedEmail: email,
        tokenEmail: decoded.email,
      });
      return res.json({ success: false, message: "Invalid session" });
    }

    const admin = await Admin.findById(decoded.adminId);

    if (
      !admin ||
      String(admin.tenantId) !== String(decoded.tenantId) ||
      admin.email !== decoded.email ||
      admin.otp !== otp ||
      admin.otpExpiry < new Date()
    ) {
      logger.warn("MFA failed: Invalid or expired OTP", { email });
      return res.json({ success: false, message: "Invalid OTP" });
    }

    const authConfig = await resolveAuthConfig(admin.tenantId, admin.domainId ?? null);
    const token = issueAdminToken({
      adminId: admin._id.toString(),
      tenantId: admin.tenantId.toString(),
      role: admin.role,
      authLevel: "MFA",
      domainAdminId: admin.role === "DOMAIN_ADMIN" ? admin._id.toString() : null,
      expiresIn: `${authConfig.sessionRules.timeoutMinutes}m`,
    });

    admin.otp = null;
    admin.otpExpiry = null;
    admin.lastActivityAt = new Date();
    await admin.save();

    res.cookie("jwt", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
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
        token,
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

// Logout
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

// Resend OTP
router.post("/resend-otp", async (req, res) => {
  logger.info("OTP resend requested");

  try {
    const { sessionToken } = req.body;
    const decoded = verifyAdminMfaSessionToken(sessionToken);
    const email = decoded.email;

    const admin = await Admin.findById(decoded.adminId);

    if (
      !admin ||
      String(admin.tenantId) !== String(decoded.tenantId) ||
      admin.email !== decoded.email
    ) {
      logger.warn("OTP resend failed: Invalid session or user not found", {
        email,
      });
      return res.json({ success: false, message: "Invalid session" });
    }

    // Generate secure OTP
    const otp = generateOTP();

    admin.otp = otp;
    admin.otpExpiry = new Date(Date.now() + 5 * 60 * 1000);
    await admin.save();

    // Send the email
    await sendOTPEmail(email, otp);

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

// Get current session (me)
router.get("/me", requireAuth, enforceAuthPolicy, async (req, res) => {
  logger.info("Validating current session (/me endpoint)");

  try {
    const admin = await Admin.findById(req.user.adminId);

    if (!admin) {
      logger.warn("Session validation failed: Admin not found", {
        adminId: req.user.adminId,
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
