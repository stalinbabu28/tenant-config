import Domain from "../models/Domain.js";

export const isCycle = async (domainId, newParentId) => {
  if (!newParentId) return false;

  let current = newParentId;

  while (current) {
    if (current.toString() === domainId.toString()) {
      return true; // cycle detected
    }

    const parent = await Domain.findById(current);
    current = parent?.parentDomainId;
  }

  return false;
};