import mongoose from "mongoose";

const mailingListSchema = new mongoose.Schema(
  {
    tenantId: {
      type: mongoose.Schema.Types.ObjectId,
      required: true,
      index: true,
    },

    listName: {
      type: String,
      required: true,
    },

    domainLinkedId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Domain",
      required: true,
      index: true,
    },

    dynamicRule: {
      action: {
        type: String,
        enum: ["AUTO_ADD", "APPROVAL_REQUIRED"],
        required: true,
      },
      includeChildren: {
        type: Boolean,
        required: true,
      },
    },

    isActive: {
      type: Boolean,
      default: true,
    },
  },
  { timestamps: true },
);

export default mongoose.model("MailingList", mailingListSchema);
