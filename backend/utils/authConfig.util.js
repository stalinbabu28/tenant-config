import AuthConfig from "../models/AuthConfig.js";

export const DEFAULT_AUTH_CONFIG = {
  loginMethods: {
    emailPassword: true,
    googleSSO: false,
    otpLogin: false,
  },
  passwordPolicy: {
    minLength: 8,
    requireUppercase: true,
    requireNumbers: true,
    requireSpecialChar: false,
    expiryDays: 90,
  },
  mfa: {
    enabled: false,
    methods: [],
  },
  sessionRules: {
    timeoutMinutes: 60,
    maxLoginAttempts: 5,
    lockoutDurationMinutes: 15,
  },
  allowedRoles: ["TENANT_ADMIN", "DOMAIN_ADMIN"],
};

export const resolveAuthConfig = async (tenantId, domainId) => {
  const query = { tenantId, domainId: domainId ?? null };
  let config = await AuthConfig.findOne(query);

  if (config) {
    return config;
  }

  if (domainId) {
    config = await AuthConfig.findOne({ tenantId, domainId: null });
    if (config) {
      return config;
    }
  }

  return await AuthConfig.create({
    tenantId,
    domainId: null,
    ...DEFAULT_AUTH_CONFIG,
  });
};

export const mapAuthConfig = (config) => ({
  tenantId: config.tenantId.toString(),
  domainId: config.domainId?.toString() ?? null,
  passwordEnabled: config.loginMethods.emailPassword,
  ssoEnabled: config.loginMethods.googleSSO,
  otpEnabled: config.loginMethods.otpLogin,
  mfaEnabled: config.mfa.enabled,
  passwordPolicy: {
    minLength: config.passwordPolicy.minLength,
    requireUppercase: config.passwordPolicy.requireUppercase,
    requireNumbers: config.passwordPolicy.requireNumbers,
    requireSpecialChars: config.passwordPolicy.requireSpecialChar,
    expiryDays: config.passwordPolicy.expiryDays,
  },
  sessionTimeoutMinutes: config.sessionRules.timeoutMinutes,
  maxLoginAttempts: config.sessionRules.maxLoginAttempts,
  lockoutDurationMinutes: config.sessionRules.lockoutDurationMinutes,
  allowedRoles: config.allowedRoles ?? [],
});
