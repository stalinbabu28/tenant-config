import express from "express";
import mongoose from "mongoose";
import Domain from "../models/Domain.js";

const router = express.Router();

const buildTree = (nodes, parentId = null) => {
  return nodes
    .filter((node) => {
      if (parentId === null) {
        return node.parentDomainId === null;
      }
      return node.parentDomainId?.toString() === parentId.toString();
    })
    .map((node) => ({
      ...node.toObject(),
      children: buildTree(nodes, node._id),
    }));
};

router.get("/tree/:tenantId", async (req, res) => {
  try {
    const tenantId = new mongoose.Types.ObjectId(req.params.tenantId);
    const domains = await Domain.find({ tenantId }).sort({ createdAt: 1 });
    res.json({ success: true, data: buildTree(domains) });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

router.post("/", async (req, res) => {
  try {
    const { tenantId, domainName, parentDomainId, domainAdminId, metadata } =
      req.body;
    const domain = await Domain.create({
      tenantId: new mongoose.Types.ObjectId(tenantId),
      domainName,
      parentDomainId: parentDomainId
        ? new mongoose.Types.ObjectId(parentDomainId)
        : null,
      domainAdminId: domainAdminId
        ? new mongoose.Types.ObjectId(domainAdminId)
        : null,
      metadata: {
        domainType: metadata?.domainType || "DEPARTMENT",
        description: metadata?.description || "",
      },
    });

    res.json({ success: true, data: domain });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

router.put("/:domainId", async (req, res) => {
  try {
    const domainId = new mongoose.Types.ObjectId(req.params.domainId);
    const updates = {};

    if (typeof req.body.domainName === "string") {
      updates.domainName = req.body.domainName;
    }

    if (Object.prototype.hasOwnProperty.call(req.body, "parentDomainId")) {
      updates.parentDomainId = req.body.parentDomainId
        ? new mongoose.Types.ObjectId(req.body.parentDomainId)
        : null;
    }

    if (Object.prototype.hasOwnProperty.call(req.body, "domainAdminId")) {
      updates.domainAdminId = req.body.domainAdminId
        ? new mongoose.Types.ObjectId(req.body.domainAdminId)
        : null;
    }

    if (req.body.metadata) {
      updates.metadata = {
        domainType: req.body.metadata.domainType || "DEPARTMENT",
        description: req.body.metadata.description || "",
      };
    }

    const updated = await Domain.findByIdAndUpdate(domainId, updates, {
      new: true,
    });

    if (!updated) {
      return res
        .status(404)
        .json({ success: false, message: "Domain not found" });
    }

    res.json({ success: true, data: updated });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

router.delete("/:domainId", async (req, res) => {
  try {
    const domainId = new mongoose.Types.ObjectId(req.params.domainId);
    const deleted = await Domain.findByIdAndDelete(domainId);

    if (!deleted) {
      return res
        .status(404)
        .json({ success: false, message: "Domain not found" });
    }

    res.json({ success: true, message: "Domain deleted successfully" });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

export default router;
