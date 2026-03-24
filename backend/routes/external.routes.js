import express from "express";
import AuthConfig from "../models/AuthConfig.js";
import mongoose from "mongoose";
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
        data: config
      });

    } catch (err) {
      res.status(500).json({ success: false, message: err.message });
    }
  }
);

export default router;