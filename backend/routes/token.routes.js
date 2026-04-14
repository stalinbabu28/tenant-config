import express from "express";
import Client from "../models/Client.js";
import { generateServiceToken } from "../utils/jwt.util.js";
import bcrypt from "bcrypt";

const router = express.Router();

router.post("/token", async (req, res) => {
  try {
    const { clientId, clientSecret } = req.body;
    const normalizedClientId =
      typeof clientId === "string" ? clientId.trim() : "";
    const normalizedSecret =
      typeof clientSecret === "string" ? clientSecret : "";

    if (!normalizedClientId || !normalizedSecret) {
      return res.status(400).json({
        success: false,
        message: "clientId and clientSecret are required",
      });
    }

    const client = await Client.findOne({
      clientId: { $eq: normalizedClientId },
    });

    if (!client) {
      return res.status(401).json({
        success: false,
        message: "Invalid client credentials",
      });
    }

    const storedSecret = client.clientSecret;
    const isBcryptHash =
      typeof storedSecret === "string" && storedSecret.startsWith("$2");
    const isSecretValid = isBcryptHash
      ? await bcrypt.compare(clientSecret, storedSecret)
      : storedSecret === clientSecret;

    if (!isSecretValid) {
      return res.status(401).json({
        success: false,
        message: "Invalid client credentials",
      });
    }

    if (!isBcryptHash) {
      const rehashedSecret = await bcrypt.hash(clientSecret, 10);
      await Client.updateOne(
        { _id: client._id },
        { $set: { clientSecret: rehashedSecret } },
      );
    }

    const ip = req.ip;

    if (client.allowedIPs.length && !client.allowedIPs.includes(ip)) {
      return res.status(403).json({
        success: false,
        message: "IP not allowed",
      });
    }
    // Generate JWT
    const token = generateServiceToken({
      service: client.clientId,
      scope: client.scope,
    });

    res.json({
      success: true,
      message: "Token generated",
      data: {
        accessToken: token,
        expiresIn: "10m",
      },
    });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

export default router;
