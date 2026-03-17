import mongoose from "mongoose";

const adminSchema = new mongoose.Schema({
  name: { type: String, required: true },

  email: { type: String, required: true, unique: true },

  passwordHash: { type: String, required: true },

  tenantId: {
    type: mongoose.Schema.Types.ObjectId,
    required: true
  },

  role: {
    type: String,
    enum: ["TENANT_ADMIN", "DOMAIN_ADMIN"],
    required: true
  },

  otp: String,
  otpExpiry: Date

}, { timestamps: true });

export default mongoose.model("Admin", adminSchema);