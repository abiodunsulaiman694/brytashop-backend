const { forwardTo } = require("prisma-binding");
const { hasPermission } = require("../utils");

const Query = {
  //if all you intend to do is what prisma does, no custom logic or authentication,
  //just forward it to db
  items: forwardTo("db"),
  item: forwardTo("db"),
  itemsConnection: forwardTo("db"),
  me(parent, args, ctx, info) {
    // check if there is a current user ID
    if (!ctx.request.userId) {
      return null;
    }
    return ctx.db.query.user(
      {
        where: { id: ctx.request.userId }
      },
      info
    );
  },
  async users(parent, args, ctx, info) {
    //check if they are logged in
    if (!ctx.request.userId) {
      throw new Error("Please, sign in");
    }
    //check if user has permission to query all users
    hasPermission(ctx.request.user, ["ADMIN", "PERMISSIONUPDATE"]);
    //query all users
    return ctx.db.query.users({}, info);
  },
  async order(parent, args, ctx, info) {
    //make sure they are logged in
    if (!ctx.request.userId) {
      throw new Error("You are not logged in!");
    }
    //query the current order
    const order = await ctx.db.query.order(
      {
        where: {
          id: args.id
        }
      },
      info
    );
    //check if they have the permissions to see this order
    const ownsOrder = order.user.id === ctx.request.userId;
    const hasPermissionToSeeOrder = ctx.request.user.permissions.includes(
      "ADMIN"
    );
    if (!ownsOrder && !hasPermissionToSeeOrder) {
      throw new Error("You can't see this order");
    }
    //return the order
    return order;
  },
  async orders(parent, args, ctx, info) {
    //get the user's id
    const { userId } = ctx.request;
    //check if they're logged in
    if (!userId) {
      throw new Error("You are not logged in!");
    }
    return ctx.db.query.orders(
      {
        where: {
          user: { id: userId }
        }
      },
      info
    );
  }
};

module.exports = Query;
