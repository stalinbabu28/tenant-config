import AcademicPolicy from "../models/AcademicPolicy.js";
import Domain from "../models/Domain.js";
import { createLogger } from "./logger.util.js";

const logger = createLogger("PolicyResolution");

/**
 * Recursive policy inheritance algorithm
 * Traverses domain tree from leaf to root to find effective policy
 *
 * Pe(d) = Cdirect(d) if Cdirect(d) ≠ ∅
 *         Pe(parent(d)) if parent(d) exists
 *         Ctenant otherwise
 */
export const resolveEffectivePolicy = async (
  tenantId,
  domainId,
  actionType = "EXAM_REG",
) => {
  if (!tenantId || !domainId) {
    logger.warn("Missing tenantId or domainId for policy resolution", {
      tenantId,
      domainId,
    });
    throw new Error("tenantId and domainId are required");
  }

  const normalizeObjectId = (value) => (value ? value.toString() : null);

  // Step 1: Try to find policy at the exact domain level
  let currentDomainId = normalizeObjectId(domainId);

  while (currentDomainId) {
    const policy = await AcademicPolicy.findOne({
      tenantId,
      domainId: currentDomainId,
      policyType: "ATTENDANCE",
    });

    if (policy) {
      logger.info("Policy resolved at domain level", {
        domainId: currentDomainId,
        threshold: policy.threshold,
      });
      return policy;
    }

    // Move to parent domain
    const currentDomain = await Domain.findOne({
      _id: currentDomainId,
      tenantId,
    }).select("parentDomainId");

    if (!currentDomain?.parentDomainId) {
      break;
    }

    currentDomainId = normalizeObjectId(currentDomain.parentDomainId);
  }

  // Step 2: Fall back to tenant-level policy
  const tenantPolicy = await AcademicPolicy.findOne({
    tenantId,
    domainId: null,
    policyType: "ATTENDANCE",
  });

  if (tenantPolicy) {
    logger.info("Policy resolved at tenant level", {
      tenantId: tenantId.toString(),
      threshold: tenantPolicy.threshold,
    });
    return tenantPolicy;
  }

  // Step 3: If no policy exists, create a default one
  logger.info("No policy found, creating default tenant policy", { tenantId });
  const defaultPolicy = await AcademicPolicy.create({
    tenantId,
    domainId: null,
    policyType: "ATTENDANCE",
    threshold: 75, // Default 75% attendance
    isHardConstraint: true,
    actionRestrictions: ["EXAM_REG", "COURSE_ENROLLMENT"],
    metadata: {
      description: "Default tenant policy",
      updatedAt: new Date(),
    },
  });

  return defaultPolicy;
};

/**
 * Get all policies for a tenant with their domain mappings
 */
export const getTenantPolicies = async (tenantId) => {
  return AcademicPolicy.find({ tenantId }).populate(
    "domainId",
    "domainName parentDomainId",
  );
};

/**
 * Get domain-specific policy
 */
export const getDomainPolicy = async (tenantId, domainId) => {
  return AcademicPolicy.findOne({
    tenantId,
    domainId,
    policyType: "ATTENDANCE",
  });
};

/**
 * Create or update a policy
 */
export const upsertPolicy = async (tenantId, domainId, policyData) => {
  const existingPolicy = await AcademicPolicy.findOne({
    tenantId,
    domainId: domainId || null,
  });

  if (existingPolicy) {
    Object.assign(existingPolicy, {
      ...policyData,
      "metadata.updatedAt": new Date(),
    });
    return existingPolicy.save();
  }

  return AcademicPolicy.create({
    tenantId,
    domainId: domainId || null,
    ...policyData,
    metadata: {
      updatedAt: new Date(),
    },
  });
};

/**
 * Delete a policy
 */
export const deletePolicy = async (policyId) => {
  return AcademicPolicy.findByIdAndDelete(policyId);
};
