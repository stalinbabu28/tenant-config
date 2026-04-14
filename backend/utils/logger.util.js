const ALLOWED_META_KEYS = new Set(["count", "error"]);

const sanitizeMeta = (meta = {}) =>
  Object.fromEntries(
    Object.entries(meta).filter(([key]) => ALLOWED_META_KEYS.has(key)),
  );

export const createLogger = (component) => {
  const log = (level, msg, meta = {}) => {
    const safeMeta = sanitizeMeta(meta);
    const payload = {
      timestamp: new Date().toISOString(),
      level,
      component,
      message: msg,
      ...(Object.keys(safeMeta).length ? { meta: safeMeta } : {}),
    };
    const output = JSON.stringify(payload);

    if (level === "ERROR") {
      console.error(output);
    } else if (level === "WARN") {
      console.warn(output);
    } else {
      console.log(output);
    }
  };

  return {
    info: (msg, meta) => log("INFO", msg, meta),
    warn: (msg, meta) => log("WARN", msg, meta),
    error: (msg, meta) => log("ERROR", msg, meta),
  };
};
