import express from "express";
import mongoose from "mongoose";
import MailingList from "../models/MailingList.js";

const router = express.Router();

// 2.1 Fetch Mailing Lists
// Endpoint: GET /api/mailing-lists/:tenantId
router.get("/:tenantId", async (req, res) => {
  try {
    // Validate that the tenantId parameter is a valid MongoDB ObjectId
    if (!mongoose.Types.ObjectId.isValid(req.params.tenantId)) {
      return res
        .status(400)
        .json({ success: false, message: "Invalid Tenant ID format." });
    }

    // Retrieves all mailing lists for a tenant.
    const lists = await MailingList.find({ tenantId: req.params.tenantId });

    // Response (200 OK)
    res.status(200).json(lists);
  } catch (error) {
    res
      .status(500)
      .json({ success: false, message: "Server error", error: error.message });
  }
});

// 2.2 Create Mailing List
// Endpoint: POST /api/mailing-lists
router.post("/", async (req, res) => {
  try {
    const { tenantId, listName, domainLinkedId, dynamicRule, isActive } =
      req.body;

    if (
      !tenantId ||
      !listName ||
      !domainLinkedId ||
      !dynamicRule ||
      typeof dynamicRule.action !== "string" ||
      typeof dynamicRule.includeChildren !== "boolean"
    ) {
      return res.status(400).json({
        success: false,
        message:
          "tenantId, listName, domainLinkedId, and valid dynamicRule are required.",
      });
    }

    if (!mongoose.Types.ObjectId.isValid(tenantId)) {
      return res
        .status(400)
        .json({ success: false, message: "Invalid Tenant ID format." });
    }

    if (!mongoose.Types.ObjectId.isValid(domainLinkedId)) {
      return res
        .status(400)
        .json({ success: false, message: "Invalid Linked Domain ID format." });
    }

    const listPayload = {
      tenantId: new mongoose.Types.ObjectId(tenantId),
      listName: String(listName).trim(),
      domainLinkedId: new mongoose.Types.ObjectId(domainLinkedId),
      dynamicRule: {
        action: String(dynamicRule.action),
        includeChildren: dynamicRule.includeChildren,
      },
      isActive: typeof isActive === "boolean" ? isActive : true,
    };

    const newList = await MailingList.create(listPayload);
    res.status(201).json(newList);
  } catch (error) {
    res.status(400).json({
      success: false,
      message: "Failed to create mailing list",
      error: error.message,
    });
  }
});

// 2.3 Update Mailing List Rules
// Endpoint: PUT /api/mailing-lists/:id
router.put("/:id", async (req, res) => {
  try {
    // Validate that the mailing list ID parameter is a valid MongoDB ObjectId
    if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
      return res
        .status(400)
        .json({ success: false, message: "Invalid Mailing List ID format." });
    }

    const existingList = await MailingList.findById(req.params.id);

    if (!existingList) {
      return res
        .status(404)
        .json({ success: false, message: "Mailing list not found" });
    }

    // Check if includeChildren is changing (Requires background job trigger)
    const oldIncludeChildren = existingList.dynamicRule?.includeChildren;
    const newIncludeChildren = req.body.dynamicRule?.includeChildren;

    const isIncludeChildrenChanged =
      newIncludeChildren !== undefined &&
      oldIncludeChildren !== newIncludeChildren;

    // Updates settings such as isActive or dynamicRule.
    const updatePayload = {};
    if (typeof req.body.listName === "string" && req.body.listName.trim()) {
      updatePayload.listName = req.body.listName.trim();
    }
    if (
      typeof req.body.domainLinkedId === "string" &&
      mongoose.Types.ObjectId.isValid(req.body.domainLinkedId)
    ) {
      updatePayload.domainLinkedId = new mongoose.Types.ObjectId(
        req.body.domainLinkedId,
      );
    }
    if (typeof req.body.isActive === "boolean") {
      updatePayload.isActive = req.body.isActive;
    }
    if (req.body.dynamicRule !== undefined) {
      if (
        typeof req.body.dynamicRule !== "object" ||
        typeof req.body.dynamicRule.action !== "string" ||
        typeof req.body.dynamicRule.includeChildren !== "boolean"
      ) {
        return res.status(400).json({
          success: false,
          message:
            "dynamicRule must be an object with action and includeChildren fields.",
        });
      }
      updatePayload.dynamicRule = {
        action: String(req.body.dynamicRule.action),
        includeChildren: req.body.dynamicRule.includeChildren,
      };
    }

    if (!Object.keys(updatePayload).length) {
      return res.status(400).json({
        success: false,
        message: "No valid fields were provided for the mailing list update.",
      });
    }

    const updatedList = await MailingList.findByIdAndUpdate(
      req.params.id,
      updatePayload,
      { new: true, runValidators: true },
    );

    // If includeChildren changes, the backend must trigger a background job to reconcile the list members.
    if (isIncludeChildrenChanged) {
      // TODO: Dispatch background job/event here (e.g., BullMQ, AWS SQS, or simple EventEmitter)
      console.log(
        `[BACKGROUND JOB TRIGGERED] Reconciling roster for list: ${updatedList._id} due to includeChildren change.`,
      );
    }

    res.status(200).json(updatedList);
  } catch (error) {
    res.status(400).json({
      success: false,
      message: "Failed to update mailing list",
      error: error.message,
    });
  }
});

export default router;
