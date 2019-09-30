const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { randomBytes } = require("crypto");
const { promisify } = require("util"); //converts callback fns to promise-based
const { hasPermission } = require("../utils");
const { makeANiceEmail, transport } = require("../mail");
const stripe = require("../stripe");
const paystack = require("../paystack");

const Mutations = {
  async createItem(parent, args, ctx, info) {
    //TODO: Check if they are logged in!
    if (!ctx.request.userId) {
      throw new Error("You must be logged in to do that!");
    }
    console.log({ args });

    const item = await ctx.db.mutation.createItem(
      {
        data: {
          // create a relationship between item and user
          user: {
            connect: {
              id: ctx.request.userId
            }
          },
          ...args.data
        }
      },
      info
    );
    return item;
  },
  updateItem(parent, args, ctx, info) {
    //take a copy of the update
    const updates = { ...args };
    //remove the ID from the updates
    delete updates.id;
    //run the update method
    return ctx.db.mutation.updateItem(
      {
        data: updates.data,
        where: { id: args.id }
      },
      info
    );
  },
  async deleteItem(parent, args, ctx, info) {
    const where = { id: args.id };
    //find the item
    const item = await ctx.db.query.item(
      { where },
      `
    {
      id
      title
      user {id}
    }
    `
    );

    //check if they own th item/have permissions
    const ownsItem = (item.user.id = ctx.request.userId);
    const hasPermissions = ctx.request.user.permissions.some(permission =>
      ["ADMIN", "ITEMDELETE"].includes(permission)
    );
    if (!ownsItem && !hasPermissions) {
      throw new Error("You don't have permission to do that");
    }

    //delete it
    return ctx.db.mutation.deleteItem({ where }, info);
  },
  async signup(parent, args, ctx, info) {
    //lower case the email
    const { data } = args;
    console.log({ args, data });
    data.email = data.email.toLowerCase();
    //hash the password
    const password = await bcrypt.hash(data.password, 10);
    //create the user in the database
    const user = await ctx.db.mutation.createUser({
      data: {
        ...data,
        password,
        permissions: { set: ["USER", "ADMIN"] }
      },
      info
    });
    //create a JWT
    // const token = jwt.sign({ userId: user.id }, process.env.APP_SECRET);
    const token = jwt.sign({ userId: user.id }, process.env.APP_SECRET);
    //we set the jwt as a cookie on the response
    ctx.response.cookie("token", token, {
      httpOnly: true,
      maxAge: 1000 * 60 * 60 * 24 * 365 //1 year
    });
    //Finally, we return the user to the browser
    return user;
  },
  async signin(parent, { email, password }, ctx, info) {
    //check if there is a user with that email
    const user = await ctx.db.query.user({
      where: { email }
    });
    if (!user) {
      throw new Error(`No such user found for email ${email}`);
    }
    //check if their password is correct
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) {
      throw new Error("Invalid Password!");
    }
    //generate the jwt token
    const token = jwt.sign({ userId: user.id }, process.env.APP_SECRET);

    //set the cookie with the token
    ctx.response.cookie("token", token, {
      httpOnly: true,
      maxAge: 1000 * 60 * 60 * 24 * 365 //1 year
    });
    //return the user
    return user;
  },
  signout(parent, args, ctx, info) {
    ctx.response.clearCookie("token");
    return {
      message: "See you soon"
    };
  },
  async requestReset(parent, args, ctx, info) {
    // 1. Check if this is a real user
    const user = await ctx.db.query.user({ where: { email: args.email } });
    if (!user) {
      throw new Error(`No such user found for email ${args.email}`);
    }
    // 2. Set a reset token and expiry on that user
    const randomBytesPromiseified = promisify(randomBytes);
    const resetToken = (await randomBytesPromiseified(20)).toString("hex");
    const resetTokenExpiry = Date.now() + 3600000; // 1 hour from now
    const res = await ctx.db.mutation.updateUser({
      where: { email: args.email },
      data: { resetToken, resetTokenExpiry }
    });

    //send a mail
    const mailResponse = await transport.sendMail({
      from: "hello@brytashop.com",
      to: user.email,
      subject: "Passwod Reset Token",
      html: makeANiceEmail(`
      Your password reset token is available here: \n\n
      <a href="${process.env.FRONTEND_URL}/reset?resetToken=${resetToken}">
      Click to reset password
      </a>
      `)
    });

    // 4. Return the message
    return { message: "Thanks!" };
  },
  async resetPassword(parent, args, ctx, info) {
    // 1. check if the passwords match
    if (args.password !== args.confirmPassword) {
      throw new Error("Yo Passwords don't match!");
    }
    // 2. check if its a legit reset token
    // 3. Check if its expired
    const [user] = await ctx.db.query.users({
      where: {
        resetToken: args.resetToken,
        resetTokenExpiry_gte: Date.now() - 3600000
      }
    });
    if (!user) {
      throw new Error("This token is either invalid or expired!");
    }
    // 4. Hash their new password
    const password = await bcrypt.hash(args.password, 10);
    // 5. Save the new password to the user and remove old resetToken fields
    const updatedUser = await ctx.db.mutation.updateUser({
      where: { email: user.email },
      data: {
        password,
        resetToken: null,
        resetTokenExpiry: null
      }
    });
    // 6. Generate JWT
    const token = jwt.sign({ userId: updatedUser.id }, process.env.APP_SECRET);
    // 7. Set the JWT cookie
    ctx.response.cookie("token", token, {
      httpOnly: true,
      maxAge: 1000 * 60 * 60 * 24 * 365
    });
    // 8. return the new user
    return updatedUser;
  },
  updatePermissions(parent, args, ctx, info) {
    //Check if they are logged in
    if (!ctx.request.userId) {
      throw new Error("You must be logged in!");
    }
    //Query the current user
    // const currentUser = await ctx.db.query.user({
    //   where: {
    //     id: ctx.request.userId
    //   }
    // }, info)
    const currentUser = ctx.request.user;
    //Check if they have permissions to do this
    hasPermission(currentUser, ["ADMIN", "PERMISSIONUPDATE"]);
    //Update the permissions
    return ctx.db.mutation.updateUser(
      {
        data: {
          permissions: {
            set: args.permissions
          }
        },
        where: {
          id: args.userId
        }
      },
      info
    );
  },
  async addToCart(parent, args, ctx, info) {
    //Make sure users are signed in
    const { userId } = ctx.request;
    // if(!userId) {
    //   throw new Error("You must be sign in")
    // }
    //Query the user's current cart
    const [existingCartItem] = await ctx.db.query.cartItems({
      where: {
        user: { id: userId },
        item: { id: args.id }
      }
    });
    //Check if that item is already in their cart and increment by one it is
    if (existingCartItem) {
      return ctx.db.mutation.updateCartItem(
        {
          where: { id: existingCartItem.id },
          data: {
            quantity: existingCartItem.quantity + 1
          }
        },
        info
      );
    }
    //If it's not, create a fresh CartItem for that user
    return ctx.db.mutation.createCartItem(
      {
        data: {
          user: {
            connect: {
              id: userId
            }
          },
          item: {
            connect: {
              id: args.id
            }
          }
        }
      },
      info
    );
  },
  async removeFromCart(parent, args, ctx, info) {
    // find the cart item
    const cartItem = await ctx.db.query.cartItem(
      {
        where: { id: args.id }
      },
      `{id, user {id}}`
    );
    //make sure we find an item
    if (!cartItem) {
      throw new Error("No cart item found!");
    }
    //make sure they own that cart item
    if (cartItem.user.id !== ctx.request.userId) {
      throw new Error("Not your cart!");
    }
    //delete that cart item
    return ctx.db.mutation.deleteCartItem(
      {
        where: { id: args.id }
      },
      info
    );
  },
  async createOrder(parent, args, ctx, info) {
    console.log("creating order via paystack");
    //query current user and ensure the're signed in
    const { userId } = ctx.request;
    if (!userId) {
      throw new Error("You must be signed in to complete this order");
    }
    //const user = await ctx.request.user
    const user = await ctx.db.query.user(
      {
        where: {
          id: userId
        }
      },
      `{
      id 
      name 
      email 
      cart {
        id 
        quantity 
        item {
          id 
          title 
          price 
          image 
          largeImage 
          description 
        }
      }
    }`
    );
    //recalculate the total for the pricing
    const amount = user.cart.reduce(
      (tally, cartItem) => tally + cartItem.item.price * cartItem.quantity,
      0
    );
    //Create the stripe charge (turn token into money)
    const charge = await stripe.charges.create({
      amount,
      currency: "NGN",
      source: args.token
    });
    //Convert the CartItems to OrderItems
    const orderItems = user.cart.map(cartItem => {
      const orderItem = {
        ...cartItem.item,
        quantity: cartItem.quantity,
        user: {
          connect: {
            id: userId
          }
        },
        item: {
          connect: {
            id: cartItem.item.id
          }
        }
      };
      delete orderItem.id;
      return orderItem;
    });
    //Create the order
    const order = await ctx.db.mutation.createOrder({
      data: {
        total: charge.amount,
        charge: charge.id,
        paymentPlatform: "Stripe",
        items: {
          create: orderItems
        },
        user: {
          connect: {
            id: userId
          }
        }
      }
    });
    //Clear the user's carts and delete cart items
    const cartItemIds = user.cart.map(cartItem => cartItem.id);
    await ctx.db.mutation.deleteManyCartItems({
      where: {
        id_in: cartItemIds
      }
    });
    //Return the order to the client
    return order;
  },
  async createOrderPaystack(parent, args, ctx, info) {
    //query current user and ensure the're signed in
    console.log("I'm in");
    console.log("Im in paystack order");
    const { userId } = ctx.request;
    if (!userId) {
      throw new Error("You must be signed in to complete this order");
    }
    //const user = await ctx.request.user
    console.log("Passed validation");
    const user = await ctx.db.query.user(
      {
        where: {
          id: userId
        }
      },
      `{
      id 
      name 
      email 
      cart {
        id 
        quantity 
        item {
          id 
          title 
          price 
          image 
          largeImage 
          description 
        }
      }
    }`
    );
    //recalculate the total for the pricing
    const amount = user.cart.reduce(
      (tally, cartItem) => tally + cartItem.item.price * cartItem.quantity,
      0
    );
    console.log("About to start payment");
    const paystackVerify = promisify(paystack.transaction.verify);
    // const resetToken = (await randomBytesPromiseified(20)).toString("hex");
    await paystackVerify(args.reference, function(error, body) {
      console.log({ body, error });
      const { data } = body;
      if (error) {
        console.log(`Paystack error- ${error}`);
        throw new Error(`Paystack error: ${error}`);
      }
      if (data.status !== "success") {
        console.log(`Paystack data status- ${data.status}`);
        throw new Error(`Paystack error: ${data.status}`);
      }
      if (data.amount !== amount) {
        console.log(`Paystack amount- ${data.amount} --- ${amount}`);
        throw new Error(
          `Invalid amount. Received: '${data.currency}${data.amount}'. Expected '${data.currency}${amount}'`
        );
      }
      console.log(`Exiting Paystack callback`);
    });
    console.log(`Payment done`);
    //Convert the CartItems to OrderItems
    const orderItems = user.cart.map(cartItem => {
      const orderItem = {
        ...cartItem.item,
        quantity: cartItem.quantity,
        user: {
          connect: {
            id: userId
          }
        },
        item: {
          connect: {
            id: cartItem.item.id
          }
        }
      };
      delete orderItem.id;
      return orderItem;
    });
    console.log(`About to create order-- Order Iterms done- ${orderItems}`);
    //Create the order
    const order = await ctx.db.mutation.createOrder({
      data: {
        total: amount,
        charge: args.reference,
        reference: args.reference,
        trans: args.trans,
        transaction: args.transaction,
        trxref: args.trxref,
        paymentPlatform: "Paystack",
        items: {
          create: orderItems
        },
        user: {
          connect: {
            id: userId
          }
        }
      }
    });
    console.log(`About to create order-- Order Iterms done- ${orderItems}`);
    //Clear the user's carts and delete cart items
    const cartItemIds = user.cart.map(cartItem => cartItem.id);
    await ctx.db.mutation.deleteManyCartItems({
      where: {
        id_in: cartItemIds
      }
    });
    //Return the order to the client
    console.log(`About to return order- ${order}`);
    return order;
  }
};

module.exports = Mutations;
