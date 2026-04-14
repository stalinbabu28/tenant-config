const createDefaultDomainRepository = () => ({
  async findById(domainId) {
    if (!domainId) {
      return null;
    }

    const { default: DomainModel } = await import("../models/Domain.js");
    return DomainModel.findById(domainId)
      .select("_id tenantId parentDomainId domainAdminId")
      .lean();
  },

  async findAdminRootDomains(tenantId, adminId) {
    const { default: DomainModel } = await import("../models/Domain.js");
    return DomainModel.find({
      tenantId,
      domainAdminId: adminId,
    })
      .select("_id")
      .lean();
  },

  async findTenantDomains(tenantId) {
    const { default: DomainModel } = await import("../models/Domain.js");
    return DomainModel.find({ tenantId }).select("_id parentDomainId").lean();
  },
});

export const createDomainAccessService = ({
  domainRepository = createDefaultDomainRepository(),
} = {}) => {
  const getAdminRootDomainIds = async ({ tenantId, adminId }) => {
    const domains = await domainRepository.findAdminRootDomains(
      tenantId,
      adminId,
    );
    return domains.map((domain) => domain._id);
  };

  const isDomainWithinScope = async ({
    tenantId,
    targetDomainId,
    rootDomainIds,
  }) => {
    if (!targetDomainId) {
      return false;
    }

    const rootIdSet = new Set(rootDomainIds.map((rootId) => String(rootId)));
    let currentDomainId = targetDomainId;
    const visited = new Set();

    while (currentDomainId) {
      const domain = await domainRepository.findById(currentDomainId);

      if (!domain) {
        return false;
      }

      if (tenantId && String(domain.tenantId) !== String(tenantId)) {
        return false;
      }

      const comparableId = String(domain._id);
      if (rootIdSet.has(comparableId)) {
        return true;
      }

      if (visited.has(comparableId)) {
        return false;
      }

      visited.add(comparableId);
      currentDomainId = domain.parentDomainId;
    }

    return false;
  };

  const listAccessibleDomainIds = async ({ tenantId, rootDomainIds }) => {
    const tenantDomains = await domainRepository.findTenantDomains(tenantId);
    const childrenByParentId = new Map();

    for (const domain of tenantDomains) {
      const parentKey = domain.parentDomainId
        ? String(domain.parentDomainId)
        : null;

      if (!childrenByParentId.has(parentKey)) {
        childrenByParentId.set(parentKey, []);
      }

      childrenByParentId.get(parentKey).push(domain);
    }

    const queue = [...rootDomainIds];
    const visited = new Set();
    const accessibleDomainIds = [];

    while (queue.length) {
      const domainId = queue.shift();
      const comparableId = String(domainId);

      if (visited.has(comparableId)) {
        continue;
      }

      visited.add(comparableId);
      accessibleDomainIds.push(domainId);

      for (const child of childrenByParentId.get(comparableId) || []) {
        queue.push(child._id);
      }
    }

    return accessibleDomainIds;
  };

  return {
    getAdminRootDomainIds,
    isDomainWithinScope,
    listAccessibleDomainIds,
  };
};
