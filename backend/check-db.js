import mongoose from "mongoose";
import dotenv from "dotenv";
dotenv.config();

const uri = process.env.MONGO_URI || "mongodb://localhost:27017/tenant-config";

try {
  console.log("URI:", uri);
  await mongoose.connect(uri);
  console.log("DB:", mongoose.connection.db.databaseName);
  const collections = await mongoose.connection.db.listCollections().toArray();
  console.log(
    "Collections:",
    collections.map((c) => c.name),
  );
  for (const name of [
    "users",
    "authconfigs",
    "admins",
    "tenantusers",
    "clients",
    "domains",
  ]) {
    const exists = collections.some((c) => c.name === name);
    if (exists) {
      const count = await mongoose.connection.db
        .collection(name)
        .countDocuments();
      console.log(name, count);
    }
  }
  await mongoose.disconnect();
} catch (err) {
  console.error(err);
  process.exit(1);
}
