import express from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import mongoose from "mongoose";
import nodemailer from "nodemailer";
import crypto from "node:crypto";
import Admin from "../models/Admin.js";
import dotenv from "dotenv";
dotenv.config();
const router = express.Router();

// ── Lightweight Structured Logger ──────────────────────────────────────────────
const sanitizeMeta = (meta = {}) => {
  const allowedKeys = new Set(["count", "error"]);
  return Object.fromEntries(
    Object.entries(meta).filter(([key]) => allowedKeys.has(key)),
  );
};

const logger = {
  info: (msg, meta = {}) => {
    const safeMeta = sanitizeMeta(meta);
    const payload = {
      timestamp: new Date().toISOString(),
      level: "INFO",
      component: "Auth",
      message: msg,
      ...(Object.keys(safeMeta).length ? { meta: safeMeta } : {}),
    };
    console.log(JSON.stringify(payload));
  },
  warn: (msg, meta = {}) => {
    const safeMeta = sanitizeMeta(meta);
    const payload = {
      timestamp: new Date().toISOString(),
      level: "WARN",
      component: "Auth",
      message: msg,
      ...(Object.keys(safeMeta).length ? { meta: safeMeta } : {}),
    };
    console.warn(JSON.stringify(payload));
  },
  error: (msg, meta = {}) => {
    const safeMeta = sanitizeMeta(meta);
    const payload = {
      timestamp: new Date().toISOString(),
      level: "ERROR",
      component: "Auth",
      message: msg,
      ...(Object.keys(safeMeta).length ? { meta: safeMeta } : {}),
    };
    console.error(JSON.stringify(payload));
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

const normalizeEmail = (value) =>
  typeof value === "string" ? value.trim().toLowerCase() : "";

const normalizeString = (value) =>
  typeof value === "string" ? value.trim() : "";

const requireValidEmail = (email, res) => {
  const normalizedEmail = normalizeEmail(email);
  if (!normalizedEmail) {
    res.status(400).json({
      success: false,
      message: "Valid email is required",
    });
    return null;
  }
  return normalizedEmail;
};

const findAdminByEmail = async (email) => {
  const normalizedEmail = normalizeEmail(email);
  if (!normalizedEmail) return null;
  return Admin.findOne({ email: { $eq: normalizedEmail } });
};

const issueOtpToAdmin = async (email, admin) => {
  const otp = generateOTP();
  admin.otp = otp;
  admin.otpExpiry = new Date(Date.now() + 5 * 60 * 1000);
  await admin.save();
  await sendOTPEmail(email, otp);
  return otp;
};

// Generate a secure, random 6-digit OTP
const generateOTP = () => crypto.randomInt(100000, 999999).toString();

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
    const { name, password, domainId } = req.body;
    const normalizedEmail = normalizeEmail(email);
    const normalizedName = normalizeString(name);

    if (
      !normalizedName ||
      !normalizedEmail ||
      !password ||
      !tenantId ||
      !mongoose.Types.ObjectId.isValid(tenantId)
    ) {
      return res.status(400).json({
        success: false,
        message:
          "name, tenantId, valid email, and password are required for signup.",
      });
    }

    const hashed = await bcrypt.hash(password, 10);
    const resolvedDomainId =
      domainId && mongoose.Types.ObjectId.isValid(domainId)
        ? new mongoose.Types.ObjectId(domainId)
        : null;

    const admin = await Admin.create({
      name: normalizedName,
      email: normalizedEmail,
      passwordHash: hashed,
      tenantId: new mongoose.Types.ObjectId(tenantId),
      domainId: resolvedDomainId,
      role: role || "DOMAIN_ADMIN",
    });

    logger.info("Admin account created successfully", {
      adminId: admin._id,
      email: normalizedEmail,
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
  const normalizedEmail = requireValidEmail(email, res);
  if (!normalizedEmail) return;

  logger.info("Login attempt", { email: normalizedEmail });

  try {
    const { password } = req.body;
    const admin = await findAdminByEmail(normalizedEmail);

    if (!admin) {
      logger.warn("Login failed: User not found", { email: normalizedEmail });
      return res.json({ success: false, message: "Invalid credentials" });
    }

    const valid = await bcrypt.compare(password, admin.passwordHash);

    if (!valid) {
      logger.warn("Login failed: Invalid password", { email });
      return res.json({ success: false, message: "Invalid credentials" });
    }

    const sessionToken = jwt.sign(
      { email: normalizedEmail },
      process.env.JWT_SECRET,
      {
        expiresIn: "5m",
      },
    );

    await issueOtpToAdmin(normalizedEmail, admin);

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

// Verify MFA
router.post("/verify-mfa", async (req, res) => {
  const { email } = req.body;
  const normalizedEmail = requireValidEmail(email, res);
  if (!normalizedEmail) return;

  logger.info("MFA verification attempt", { email: normalizedEmail });

  try {
    const { otp, sessionToken } = req.body;
    const decoded = jwt.verify(sessionToken, process.env.JWT_SECRET);

    if (String(decoded.email).trim().toLowerCase() !== normalizedEmail) {
      logger.warn("MFA failed: Session email mismatch", {
        providedEmail: normalizedEmail,
        tokenEmail: decoded.email,
      });
      return res.json({ success: false, message: "Invalid session" });
    }

    const admin = await findAdminByEmail(normalizedEmail);

    if (!admin || admin.otp !== otp || admin.otpExpiry < new Date()) {
      logger.warn("MFA failed: Invalid or expired OTP", { email });
      return res.json({ success: false, message: "Invalid OTP" });
    }

    const token = jwt.sign(
      {
        adminId: admin._id,
        domainAdminId: admin.role === "DOMAIN_ADMIN" ? admin._id : null,
        tenantId: admin.tenantId,
        domainId: admin.domainId ?? null,
        role: admin.role,
      },
      process.env.JWT_SECRET,
      { expiresIn: "24h" },
    );

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
        admin: {
          id: admin._id,
          name: admin.name,
          email: admin.email,
          tenantId: admin.tenantId,
          domainId: admin.domainId,
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
    const decoded = jwt.verify(sessionToken, process.env.JWT_SECRET);
    const email = normalizeEmail(decoded.email);

    if (!email) {
      return res.status(400).json({
        success: false,
        message: "Invalid session email",
      });
    }

    const admin = await findAdminByEmail(email);

    if (!admin) {
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
