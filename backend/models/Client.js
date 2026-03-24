import mongoose from "mongoose";

const clientSchema = new mongoose.Schema({
  clientId: {
    type: String,
    required: true,
    unique: true
  },

  clientSecret: {
    type: String,
    required: true
  },

  scope: {
    type: [String],
    default: []
  },

  allowedIPs: {
    type: [String],
    default: []
  }

}, { timestamps: true });

export default mongoose.model("Client", clientSchema);