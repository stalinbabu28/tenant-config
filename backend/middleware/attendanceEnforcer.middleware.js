import AuditLog from "../models/AuditLog.js";
import { resolveEffectivePolicy } from "../utils/policyResolution.util.js";
import { createLogger } from "../utils/logger.util.js";

const logger = createLogger("AttendanceEnforcer");

/**
 * Attendance Enforcement Middleware
 * This middleware enforces attendance policies at the gateway level
 * Ensures no request bypasses the policy check
 */
export const attendanceEnforcer = async (req, res, next) => {
  try {
    // Extract user context
    const { studentId, domainId, tenantId } = req.user;
    const targetAction = req.path;
    const ipAddress = req.ip || req.connection.remoteAddress;
    const userAgent = req.get("user-agent");

    if (!studentId || !domainId || !tenantId) {
      logger.warn("Missing required user context", {
        hasStudentId: !!studentId,
        hasDomainId: !!domainId,
        hasTenantId: !!tenantId,
      });
      return res.status(400).json({
        error: "INVALID_CONTEXT",
        message: "Missing studentId, domainId, or tenantId",
      });
    }

    // Step 1: Resolve effective policy for the domain
    const policy = await resolveEffectivePolicy(
      tenantId,
      domainId,
      targetAction,
    );

    if (!policy) {
      logger.warn("No policy found for domain", {
        tenantId: tenantId.toString(),
        domainId: domainId.toString(),
      });
      return res.status(500).json({
        error: "POLICY_NOT_FOUND",
        message: "No attendance policy configured for this domain",
      });
    }

    // Step 2: Fetch actual attendance from ERP (simulated via header or external API)
    // In production, this would call: await erpInternalService.getAttendance(studentId)
    const actualAttendanceHeader = req.get("x-student-attendance");
    const actualAttendance = actualAttendanceHeader
      ? parseFloat(actualAttendanceHeader)
      : null;

    if (actualAttendance === null || isNaN(actualAttendance)) {
      logger.warn("Attendance data missing or invalid", {
        studentId,
        header: actualAttendanceHeader,
      });
      return res.status(400).json({
        error: "ATTENDANCE_DATA_MISSING",
        message: "Student attendance data not found",
      });
    }

    // Step 3: Enforce the policy
    const meetsThreshold = actualAttendance >= policy.threshold;
    const decision = meetsThreshold ? "ALLOWED" : "DENIED";

    // Step 4: Log the decision asynchronously (non-blocking)
    logAuditDecision({
      tenantId,
      studentId,
      domainId,
      policyId: policy._id,
      action: targetAction,
      requestPath: req.originalUrl,
      actualAttendance,
      requiredThreshold: policy.threshold,
      decision,
      reasonForDenial: meetsThreshold
        ? null
        : `Attendance ${actualAttendance}% below required threshold ${policy.threshold}%`,
      ipAddress,
      userAgent,
    }).catch((err) => {
      logger.error("Failed to log audit decision", {
        error: err.message,
        studentId,
      });
    });

    // Step 5: Decision logic
    if (!meetsThreshold) {
      logger.warn("Policy violation detected", {
        studentId,
        domainId: domainId.toString(),
        attendance: actualAttendance,
        threshold: policy.threshold,
        policyId: policy._id.toString(),
      });

      return res.status(403).json({
        error: "POLICY_VIOLATION",
        message: `Required attendance: ${policy.threshold}%. Your attendance: ${actualAttendance}%`,
        policyId: policy._id.toString(),
        currentAttendance: actualAttendance,
        requiredAttendance: policy.threshold,
      });
    }

    // Attach policy context to request for downstream use
    req.appliedPolicy = {
      policyId: policy._id.toString(),
      threshold: policy.threshold,
      actualAttendance,
    };

    logger.info("Policy check passed", {
      studentId,
      attendance: actualAttendance,
      threshold: policy.threshold,
    });

    next();
  } catch (error) {
    logger.error("Attendance enforcer error", {
      error: error.message,
      path: req.path,
    });

    res.status(500).json({
      error: "ENFORCEMENT_ERROR",
      message: "Policy enforcement failed",
    });
  }
};

/**
 * Log audit decision asynchronously
 */
async function logAuditDecision(auditData) {
  try {
    await AuditLog.create(auditData);
  } catch (error) {
    logger.error("Audit logging failed", { error: error.message });
    // Don't throw - this should not block the normal request flow
  }
}

/**
 * Middleware to skip enforcement for non-restricted actions
 */
export const shouldEnforcePolicy = (restrictedPaths = []) => {
  return (req, res, next) => {
    const pathRequiresEnforcement = restrictedPaths.some((path) =>
      req.path.startsWith(path),
    );

    if (!pathRequiresEnforcement) {
      return next();
    }

    attendanceEnforcer(req, res, next);
  };
};
