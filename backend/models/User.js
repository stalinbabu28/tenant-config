import mongoose from "mongoose";

const userSchema = new mongoose.Schema(
  {
    name: { type: String, required: true },

    email: { type: String, required: true, unique: true },

    passwordHash: { type: String, required: true },

    tenantId: {
      type: mongoose.Schema.Types.ObjectId,
      required: true,
    },

    domainId: {
      type: mongoose.Schema.Types.ObjectId,
      default: null,
    },

    failedLoginAttempts: {
      type: Number,
      default: 0,
    },
    lockoutUntil: Date,
    lastActivityAt: {
      type: Date,
      default: Date.now,
    },
    otp: String,
    otpExpiry: Date,
    totpSecret: String,
  },
  { timestamps: true },
);

export default mongoose.model("User", userSchema, "tenantusers");
