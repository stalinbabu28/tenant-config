import mongoose from "mongoose";

const authConfigSchema = new mongoose.Schema(
  {
    tenantId: {
      type: mongoose.Schema.Types.ObjectId,
      required: true,
    },

    domainId: {
      type: mongoose.Schema.Types.ObjectId,
      default: null,
    },

    loginMethods: {
      emailPassword: { type: Boolean, default: true },
      googleSSO: { type: Boolean, default: false },
      otpLogin: { type: Boolean, default: false },
    },

    passwordPolicy: {
      minLength: { type: Number, default: 8 },
      requireUppercase: { type: Boolean, default: true },
      requireNumbers: { type: Boolean, default: true },
      requireSpecialChar: { type: Boolean, default: false },
      expiryDays: { type: Number, default: 90 },
    },

    mfa: {
      enabled: { type: Boolean, default: false },
      methods: [{ type: String }],
    },

    sessionRules: {
      timeoutMinutes: { type: Number, default: 30 },
      maxLoginAttempts: { type: Number, default: 5 },
      lockoutDurationMinutes: { type: Number, default: 15 },
    },

    allowedRoles: {
      type: [String],
      default: [],
    },
  },
  { timestamps: true },
);

authConfigSchema.index({ tenantId: 1, domainId: 1 }, { unique: true });

export default mongoose.model("AuthConfig", authConfigSchema);
