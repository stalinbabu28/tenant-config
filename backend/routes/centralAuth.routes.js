import express from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import mongoose from "mongoose";
import User from "../models/User.js";
import { sendOTPEmail } from "../utils/email.util.js";
import { resolveAuthConfig, mapAuthConfig } from "../utils/authConfig.util.js";

const router = express.Router();

const generateOTP = () =>
  Math.floor(100000 + Math.random() * 900000).toString();

const isLockedOut = (entity) =>
  !!entity.lockoutUntil && entity.lockoutUntil > new Date();

const lockoutRemainingMinutes = (entity) => {
  if (!entity.lockoutUntil) return 0;
  return Math.ceil((entity.lockoutUntil - new Date()) / 60000);
};

router.post("/identify", async (req, res) => {
  try {
    const { tenantId, email } = req.body;
    if (!tenantId || !email) {
      return res.status(400).json({
        success: false,
        message: "tenantId and email are required",
      });
    }

    const tenantObjectId = new mongoose.Types.ObjectId(tenantId);
    const user = await User.findOne({ email, tenantId: tenantObjectId });

    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found for this tenant",
      });
    }

    if (isLockedOut(user)) {
      const minutes = lockoutRemainingMinutes(user);
      return res.status(403).json({
        success: false,
        message: `Account locked. Try again in ${minutes} minute${
          minutes === 1 ? "" : "s"
        }.`,
      });
    }

    const authConfig = await resolveAuthConfig(tenantObjectId, user.domainId);

    res.json({
      success: true,
      data: {
        email: user.email,
        tenantId,
        domainId: user.domainId?.toString() ?? null,
        role: user.role,
        authConfig: mapAuthConfig(authConfig),
      },
    });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

router.post("/signup", async (req, res) => {
  try {
    const { tenantId, name, email, password } = req.body;
    if (!tenantId || !name || !email || !password) {
      return res.status(400).json({
        success: false,
        message: "tenantId, name, email, and password are required",
      });
    }

    const tenantObjectId = new mongoose.Types.ObjectId(tenantId);
    const existingUser = await User.findOne({
      email,
      tenantId: tenantObjectId,
    });
    if (existingUser) {
      return res.status(409).json({
        success: false,
        message: "A user with this email already exists for the tenant.",
      });
    }

    // Validate password against policy
    const authConfig = await resolveAuthConfig(tenantObjectId, null);
    if (!authConfig) {
      return res.status(400).json({
        success: false,
        message: "Auth configuration not found for tenant.",
      });
    }

    const { passwordPolicy } = authConfig;
    if (password.length < passwordPolicy.minLength) {
      return res.status(400).json({
        success: false,
        message: `Password must be at least ${passwordPolicy.minLength} characters long.`,
      });
    }
    if (passwordPolicy.requireUppercase && !/[A-Z]/.test(password)) {
      return res.status(400).json({
        success: false,
        message: "Password must contain at least one uppercase letter.",
      });
    }
    if (passwordPolicy.requireNumbers && !/\d/.test(password)) {
      return res.status(400).json({
        success: false,
        message: "Password must contain at least one number.",
      });
    }
    if (
      passwordPolicy.requireSpecialChar &&
      !/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)
    ) {
      return res.status(400).json({
        success: false,
        message: "Password must contain at least one special character.",
      });
    }

    const passwordHash = await bcrypt.hash(password, 10);
    await User.create({
      name,
      email,
      passwordHash,
      tenantId: tenantObjectId,
      role: "USER",
    });

    res.json({
      success: true,
      message: "User account created. You can now sign in.",
    });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

router.post("/login", async (req, res) => {
  try {
    const { tenantId, email, password } = req.body;
    if (!tenantId || !email) {
      return res.status(400).json({
        success: false,
        message: "tenantId and email are required",
      });
    }

    const tenantObjectId = new mongoose.Types.ObjectId(tenantId);
    const user = await User.findOne({ email, tenantId: tenantObjectId });

    if (!user) {
      return res
        .status(401)
        .json({ success: false, message: "Invalid credentials" });
    }

    if (isLockedOut(user)) {
      const minutes = lockoutRemainingMinutes(user);
      return res.json({
        success: false,
        message: `Account locked. Try again in ${minutes} minute${
          minutes === 1 ? "" : "s"
        }.`,
      });
    }

    const authConfig = await resolveAuthConfig(tenantObjectId, user.domainId);

    if (
      !authConfig.loginMethods.emailPassword &&
      authConfig.loginMethods.googleSSO
    ) {
      return res.json({
        success: true,
        message: "Use SSO to sign in.",
        data: { requiresSSO: true },
      });
    }

    if (authConfig.loginMethods.emailPassword) {
      if (!password) {
        return res.status(400).json({
          success: false,
          message: "Password is required for this tenant configuration",
        });
      }

      const validPassword = await bcrypt.compare(password, user.passwordHash);
      if (!validPassword) {
        user.failedLoginAttempts += 1;
        if (
          authConfig.sessionRules.maxLoginAttempts > 0 &&
          user.failedLoginAttempts >= authConfig.sessionRules.maxLoginAttempts
        ) {
          user.lockoutUntil = new Date(
            Date.now() + authConfig.sessionRules.lockoutDurationMinutes * 60000,
          );
          await user.save();
          return res.json({
            success: false,
            message: `Account locked for ${authConfig.sessionRules.lockoutDurationMinutes} minutes after ${authConfig.sessionRules.maxLoginAttempts} failed attempt${
              authConfig.sessionRules.maxLoginAttempts === 1 ? "" : "s"
            }.`,
          });
        }

        await user.save();
        return res
          .status(401)
          .json({ success: false, message: "Invalid credentials" });
      }

      user.failedLoginAttempts = 0;
      user.lockoutUntil = null;
    } else if (!authConfig.loginMethods.otpLogin) {
      return res.status(403).json({
        success: false,
        message: "No supported login method is enabled for this tenant",
      });
    }

    if (authConfig.mfa.enabled || authConfig.loginMethods.otpLogin) {
      const otp = generateOTP();
      user.otp = otp;
      user.otpExpiry = new Date(Date.now() + 5 * 60 * 1000);
      user.lastActivityAt = new Date();
      await user.save();

      try {
        await sendOTPEmail(user.email, otp);
      } catch (sendErr) {
        return res.status(500).json({
          success: false,
          message: "Unable to deliver OTP email",
        });
      }

      const sessionToken = jwt.sign(
        { email: user.email, tenantId },
        process.env.JWT_SECRET,
        {
          expiresIn: "5m",
        },
      );

      return res.json({
        success: true,
        message: "OTP has been sent to your email.",
        data: {
          requiresMFA: true,
          sessionToken,
        },
      });
    }

    user.lastActivityAt = new Date();
    await user.save();

    const token = jwt.sign(
      {
        userId: user._id,
        tenantId: user.tenantId,
        domainId: user.domainId,
        role: "USER",
        authMethods: ["password"],
      },
      process.env.JWT_SECRET,
      {
        expiresIn: `${authConfig.sessionRules.timeoutMinutes}m`,
      },
    );

    return res.json({
      success: true,
      message: `Authentication successful. Session expires after ${authConfig.sessionRules.timeoutMinutes} minute${
        authConfig.sessionRules.timeoutMinutes === 1 ? "" : "s"
      } of inactivity.`,
      data: {
        token,
      },
    });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

router.post("/verify-otp", async (req, res) => {
  try {
    const { email, sessionToken, otp } = req.body;
    if (!email || !sessionToken || !otp) {
      return res.status(400).json({
        success: false,
        message: "email, sessionToken, and otp are required",
      });
    }

    const decoded = jwt.verify(sessionToken, process.env.JWT_SECRET);
    if (decoded.email !== email) {
      return res
        .status(401)
        .json({ success: false, message: "Invalid session" });
    }

    const user = await User.findOne({ email });
    if (!user || user.otp !== otp || user.otpExpiry < new Date()) {
      return res
        .status(401)
        .json({ success: false, message: "Invalid or expired OTP" });
    }

    const authConfig = await resolveAuthConfig(user.tenantId, user.domainId);
    const authToken = jwt.sign(
      {
        userId: user._id,
        tenantId: user.tenantId,
        domainId: user.domainId,
        role: "USER",
        authMethods: ["otp"],
        mfaPassed: true,
      },
      process.env.JWT_SECRET,
      { expiresIn: `${authConfig.sessionRules.timeoutMinutes}m` },
    );

    user.otp = null;
    user.otpExpiry = null;
    user.lastActivityAt = new Date();
    await user.save();

    res.json({
      success: true,
      message: `OTP verification successful. Session expires after ${authConfig.sessionRules.timeoutMinutes} minute${
        authConfig.sessionRules.timeoutMinutes === 1 ? "" : "s"
      } of inactivity.`,
      data: {
        token: authToken,
      },
    });
  } catch (err) {
    res
      .status(401)
      .json({ success: false, message: "Invalid or expired session" });
  }
});

export default router;
