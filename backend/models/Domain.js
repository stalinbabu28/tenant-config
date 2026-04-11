import mongoose from "mongoose";

const domainSchema = new mongoose.Schema(
  {
    tenantId: {
      type: mongoose.Schema.Types.ObjectId,
      required: true,
    },
    domainName: {
      type: String,
      required: true,
    },
    parentDomainId: {
      type: mongoose.Schema.Types.ObjectId,
      default: null,
    },
    domainAdminId: {
      type: mongoose.Schema.Types.ObjectId,
      default: null,
    },
    metadata: {
      domainType: {
        type: String,
        enum: ["ROOT", "DEPARTMENT", "YEAR", "SECTION"],
        default: "DEPARTMENT",
      },
      description: {
        type: String,
        default: "",
      },
    },
  },
  { timestamps: true },
);

export default mongoose.model("Domain", domainSchema);
