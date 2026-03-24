const allowedIPs = [
  "127.0.0.1",
  "::1"
  // add auth team server IP later
];

export const ipWhitelist = (req, res, next) => {
  const ip = req.ip;

  if (!allowedIPs.includes(ip)) {
    return res.status(403).json({
      success: false,
      message: "Forbidden - IP not allowed"
    });
  }

  next();
};