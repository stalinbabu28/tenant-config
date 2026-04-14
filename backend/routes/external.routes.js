import express from "express";
import AuthConfig from "../models/AuthConfig.js";
import User from "../models/User.js";
import Admin from "../models/Admin.js";
import mongoose from "mongoose";
import jwt from "jsonwebtoken";
import { externalAuth } from "../middleware/externalAuth.middleware.js";

const router = express.Router();

router.get(
  "/auth-config/:tenantId",
  externalAuth("read:auth-config"),
  async (req, res) => {
    try {
      const tenantId = new mongoose.Types.ObjectId(req.params.tenantId);

      const config = await AuthConfig.findOne({ tenantId });

      res.json({
        success: true,
        data: config,
      });
    } catch (err) {
      res.status(500).json({ success: false, message: err.message });
    }
  },
);

router.post(
  "/verify-token",
  externalAuth("verify:user-token"),
  async (req, res) => {
    try {
      const userToken = req.body?.userToken;

      if (!userToken || typeof userToken !== "string") {
        return res.status(400).json({
          success: false,
          message: "userToken is required",
        });
      }

      const decoded = jwt.verify(userToken, process.env.JWT_SECRET);

      if (!decoded?.tenantId) {
        return res.status(401).json({
          success: false,
          message: "Invalid token payload",
        });
      }

      const tenantId = decoded.tenantId;
      let tokenType = "unknown";

      if (decoded.adminId) {
        tokenType = "admin";
      } else if (decoded.userId) {
        tokenType = "user";
      }

      if (tokenType === "unknown") {
        return res.status(401).json({
          success: false,
          message: "Unsupported token type",
        });
      }

      let principal = null;

      if (tokenType === "admin") {
        principal = await Admin.findOne({
          _id: decoded.adminId,
          tenantId,
        }).select("_id name email tenantId domainId role");
      } else {
        principal = await User.findOne({
          _id: decoded.userId,
          tenantId,
        }).select("_id name email tenantId domainId role");
      }

      if (!principal) {
        return res.status(401).json({
          success: false,
          message: "Token principal no longer exists",
        });
      }

      return res.json({
        success: true,
        message: "Token is valid",
        data: {
          valid: true,
          tokenType,
          principal: {
            id: principal._id,
            name: principal.name,
            email: principal.email,
            tenantId: principal.tenantId,
            domainId: principal.domainId ?? null,
            role: principal.role,
          },
          claims: {
            iat: decoded.iat,
            exp: decoded.exp,
            authMethods: decoded.authMethods ?? [],
            mfaPassed: decoded.mfaPassed ?? false,
          },
          verifiedBy: req.external?.service ?? "unknown-service",
        },
      });
    } catch (err) {
      return res.status(401).json({
        success: false,
        message: "Invalid or expired token",
      });
    }
  },
);

export default router;
