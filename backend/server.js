import express from "express";
import mongoose from "mongoose";
import cors from "cors";
import dotenv from "dotenv";
import cookieParser from "cookie-parser";
import authRoutes from "./routes/auth.routes.js";
import AuthConfig from "./models/AuthConfig.js";
import authConfigRoutes from "./routes/authConfig.routes.js";
import { requireAuth } from "./middleware/auth.middleware.js";
import externalRoutes from "./routes/external.routes.js";
import tokenRoutes from "./routes/token.routes.js";

dotenv.config();
const app = express();

// Middleware
app.use(express.json());
app.use(cookieParser());
app.use(
  cors({
    origin: "http://localhost:5173",
    credentials: true,
  }),
);

// Routes
app.use("/api/auth-config", requireAuth, authConfigRoutes);
app.use("/api/admin", authRoutes);
app.use("/api/external", externalRoutes);
app.use("/api/token", tokenRoutes);
// Test route
app.get("/", (req, res) => {
  res.send("Backend running");
});

// MongoDB connection
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => {
    console.log("MongoDB Connected");

    app.listen(3001, () => {
      console.log("Server running on port 3001");
    });
  })
  .catch((err) => console.log(err));
