import express from "express";
import mongoose from "mongoose";
import cors from "cors";
import dotenv from "dotenv";
import cookieParser from "cookie-parser";
import authRoutes from "./routes/auth.routes.js";
import AuthConfig from "./models/AuthConfig.js";
import authConfigRoutes from "./routes/authConfig.routes.js";
import centralAuthRoutes from "./routes/centralAuth.routes.js";
import domainRoutes from "./routes/domains.routes.js";
import { requireAuth } from "./middleware/auth.middleware.js";
import externalRoutes from "./routes/external.routes.js";
import tokenRoutes from "./routes/token.routes.js";
import dns from "node:dns";
dns.setServers(["1.1.1.1", "8.8.8.8"]);
dotenv.config();
const app = express();

// Middleware
app.use(express.json());
app.use(cookieParser());
app.use(
  cors({
    origin: process.env.ALLOWED_ORIGINS.split(","),
    credentials: true,
  }),
);

// Routes
app.use("/api/auth-config", requireAuth, authConfigRoutes);
app.use("/api/domains", requireAuth, domainRoutes);
app.use("/api/central-auth", centralAuthRoutes);
app.use("/api/admin", authRoutes);
app.use("/api/external", externalRoutes);
app.use("/api/token", tokenRoutes);
app.use("/api/domains", requireAuth, domainRoutes);
app.use("/api/mailing-lists", requireAuth, mailingListRoutes);
app.get("/", (req, res) => {
  res.send("Backend running");
});

// MongoDB connection
mongoose
  .connect(process.env.MONGO_URI)
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => {
    console.log("MongoDB Connected");

    app.listen(3001, () => {
      console.log("Server running on port 3001");
    });
  })
  .catch((err) => console.log(err));
