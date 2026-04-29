import mongoose from "mongoose";

const auditLogSchema = new mongoose.Schema(
  {
    tenantId: {
      type: mongoose.Schema.Types.ObjectId,
      required: true,
      index: true,
    },
    studentId: {
      type: String,
      required: true,
      index: true,
    },
    domainId: {
      type: mongoose.Schema.Types.ObjectId,
      required: true,
      index: true,
    },
    policyId: {
      type: mongoose.Schema.Types.ObjectId,
      required: true,
    },
    action: {
      type: String,
      required: true,
    },
    requestPath: String,
    actualAttendance: {
      type: Number,
      required: true,
    },
    requiredThreshold: {
      type: Number,
      required: true,
    },
    decision: {
      type: String,
      enum: ["ALLOWED", "DENIED"],
      required: true,
    },
    reasonForDenial: String,
    timestamp: {
      type: Date,
      default: Date.now,
      index: true,
    },
    ipAddress: String,
    userAgent: String,
  },
  { timestamps: false },
);

// Create index for efficient audit querying
auditLogSchema.index({ tenantId: 1, timestamp: -1 });
auditLogSchema.index({ studentId: 1, timestamp: -1 });

export default mongoose.model("AuditLog", auditLogSchema);
