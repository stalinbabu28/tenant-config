const requestCounts = {};

export const rateLimit = (limit = 10, windowMs = 60000) => {
  return (req, res, next) => {
    const ip = req.ip;
    const now = Date.now();

    if (!requestCounts[ip]) {
      requestCounts[ip] = [];
    }

    // remove old requests
    requestCounts[ip] = requestCounts[ip].filter(
      (timestamp) => now - timestamp < windowMs
    );

    if (requestCounts[ip].length >= limit) {
      return res.status(429).json({
        success: false,
        message: "Too many requests"
      });
    }

    requestCounts[ip].push(now);

    next();
  };
};