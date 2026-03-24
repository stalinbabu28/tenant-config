import jwt from "jsonwebtoken";
import fs from "fs";

const privateKey = fs.readFileSync("./keys/private.key");
const publicKey = fs.readFileSync("./keys/public.key");

// 🔐 Generate token
export const generateServiceToken = (payload) => {
  return jwt.sign(payload, privateKey, {
    algorithm: "RS256",
    expiresIn: "10m"
  });
};

// 🔐 Verify token
export const verifyServiceToken = (token) => {
  return jwt.verify(token, publicKey, {
    algorithms: ["RS256"]
  });
};