import mongoose from "mongoose";

const academicPolicySchema = new mongoose.Schema(
  {
    tenantId: {
      type: mongoose.Schema.Types.ObjectId,
      required: true,
      index: true,
    },
    domainId: {
      type: mongoose.Schema.Types.ObjectId,
      required: true,
      index: true,
    },
    policyType: {
      type: String,
      enum: ["ATTENDANCE", "ELIGIBILITY"],
      default: "ATTENDANCE",
    },
    threshold: {
      type: Number,
      required: true,
      min: 0,
      max: 100,
    },
    isHardConstraint: {
      type: Boolean,
      default: true,
    },
    actionRestrictions: [
      {
        type: String,
      },
    ],
    metadata: {
      lastModifiedBy: mongoose.Schema.Types.ObjectId,
      updatedAt: Date,
      description: String,
    },
  },
  { timestamps: true },
);

academicPolicySchema.index({ tenantId: 1, domainId: 1 }, { unique: true });

export default mongoose.model("AcademicPolicy", academicPolicySchema);
