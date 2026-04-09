import Domain from "../models/Domain.js";
import mongoose from "mongoose";

const buildDomainForest = (roots) => {
  return roots.map((root) => {
    const allNodes = [
      {
        ...root,
        children: []
      },
      ...root.children.map((child) => ({
        ...child,
        children: []
      }))
    ];

    const byId = new Map(allNodes.map((node) => [node._id.toString(), node]));

    for (const node of allNodes) {
      if (!node.parentDomainId) continue;

      const parent = byId.get(node.parentDomainId.toString());
      if (parent) {
        parent.children.push(node);
      }
    }

    return byId.get(root._id.toString());
  });
};

export const getDomainTree = async (tenantId, rootDomainIds = []) => {
  const tenantObjectId = new mongoose.Types.ObjectId(tenantId);
  const rootObjectIds = rootDomainIds.map(
    (rootId) => new mongoose.Types.ObjectId(rootId)
  );

  const tree = await Domain.aggregate([
    {
      $match: {
        tenantId: tenantObjectId,
        ...(rootObjectIds.length
          ? { _id: { $in: rootObjectIds } }
          : { parentDomainId: null })
      }
    },
    {
      $graphLookup: {
        from: "domains",
        startWith: "$_id",
        connectFromField: "_id",
        connectToField: "parentDomainId",
        restrictSearchWithMatch: {
          tenantId: tenantObjectId
        },
        as: "children"
      }
    }
  ]);

  return buildDomainForest(tree);
};
