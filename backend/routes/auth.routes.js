import express from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import mongoose from "mongoose";
import Admin from "../models/Admin.js";

const router = express.Router();


// ✅ SIGNUP (for testing)
router.post("/signup", async (req, res) => {
  try {
    const { name, email, password, role, tenantId } = req.body;

    const hashed = await bcrypt.hash(password, 10);

    const admin = await Admin.create({
      name,
      email,
      passwordHash: hashed,
      tenantId: new mongoose.Types.ObjectId(tenantId), // ✅ FIXED
      role: role || "TENANT_ADMIN"
    });

    res.json({
      success: true,
      message: "Admin account created. Please log in."
    });

  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});


// ✅ LOGIN
router.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const admin = await Admin.findOne({ email });

    if (!admin) {
      return res.json({ success: false, message: "Invalid credentials" });
    }

    const valid = await bcrypt.compare(password, admin.passwordHash);

    if (!valid) {
      return res.json({ success: false, message: "Invalid credentials" });
    }

    const otp = "123456"; // mock OTP

    admin.otp = otp;
    admin.otpExpiry = new Date(Date.now() + 5 * 60 * 1000);
    await admin.save();

    const sessionToken = jwt.sign(
      { email },
      process.env.JWT_SECRET,
      { expiresIn: "5m" }
    );

    res.json({
      success: true,
      message: "Password verified. OTP sent to registered email.",
      data: {
        requiresMFA: true,
        sessionToken
      }
    });

  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});


// ✅ VERIFY MFA
router.post("/verify-mfa", async (req, res) => {
  try {
    const { email, otp, sessionToken } = req.body;

    const decoded = jwt.verify(sessionToken, process.env.JWT_SECRET);

    if (decoded.email !== email) {
      return res.json({ success: false, message: "Invalid session" });
    }

    const admin = await Admin.findOne({ email });

    if (!admin || admin.otp !== otp || admin.otpExpiry < new Date()) {
      return res.json({ success: false, message: "Invalid OTP" });
    }

    const token = jwt.sign(
      {
        adminId: admin._id,
        tenantId: admin.tenantId,
        role: admin.role
      },
      process.env.JWT_SECRET,
      { expiresIn: "24h" }
    );

    res.cookie("jwt", token, {
      httpOnly: true,
      secure: false,
      sameSite: "Strict"
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
          role: admin.role
          }
      }
      });

  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});


router.post("/logout", async (req, res) => {
  try {
    res.cookie("jwt", "", {
      httpOnly: true,
      secure: false,
      sameSite: "Strict",
      maxAge: 0
    });

    res.json({
      success: true,
      message: "Logged out."
    });

  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

router.post("/resend-otp", async (req, res) => {
  try {
    const { sessionToken } = req.body;

    const decoded = jwt.verify(sessionToken, process.env.JWT_SECRET);

    const admin = await Admin.findOne({ email: decoded.email });

    if (!admin) {
      return res.json({ success: false, message: "Invalid session" });
    }

    const otp = "123456";

    admin.otp = otp;
    admin.otpExpiry = new Date(Date.now() + 5 * 60 * 1000);
    await admin.save();

    res.json({
      success: true,
      message: "OTP resent to registered email."
    });

  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

router.get("/me", async (req, res) => {
  try {
    const token = req.cookies.jwt;

    if (!token) {
      return res.status(401).json({
        success: false,
        message: "Unauthorized"
      });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    const admin = await Admin.findById(decoded.adminId);

    if (!admin) {
      return res.status(401).json({
        success: false,
        message: "Invalid session"
      });
    }

    res.json({
      success: true,
      message: "Session valid.",
      data: {
        admin: {
          id: admin._id,
          name: admin.name,
          email: admin.email,
          tenantId: admin.tenantId,
          role: admin.role
        }
      }
    });

  } catch (err) {
    res.status(401).json({
      success: false,
      message: "Session expired"
    });
  }
});


export default router;