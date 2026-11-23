import "dotenv/config";
import { MongoClient } from "mongodb";
import { betterAuth } from "better-auth";
import { createAuthMiddleware, APIError } from "better-auth/api";
import { mongodbAdapter } from "@better-auth/mongo-adapter";

export const mongoClient = new MongoClient(process.env.MONGODB_URI || "mongodb://localhost:27017", {
  serverSelectionTimeoutMS: 15000,
});
export const db = mongoClient.db("wedplan");
export const users = db.collection("user");
export const services = db.collection("services");
export const bookings = db.collection("bookings");
export const transactions = db.collection("transactions");

const website = (process.env.CLIENT_URL || "http://localhost:3000").replace(/\/$/, "");
export const auth = betterAuth({
  appName: "WedPlan",
  baseURL: process.env.BETTER_AUTH_URL || website,
  basePath: "/api/auth",
  secret: process.env.BETTER_AUTH_SECRET,
  trustedOrigins: [website, "http://localhost:3000"],
  database: mongodbAdapter(db, { client: mongoClient }),
  emailAndPassword: { enabled: true, minPasswordLength: 6 },
  hooks: {
    before: createAuthMiddleware(async (ctx) => {
      if (ctx.path === "/sign-up/email") {
        const password = String(ctx.body?.password || "");
        if (password.length < 6 || !/[A-Z]/.test(password) || !/[a-z]/.test(password)) {
          throw new APIError("BAD_REQUEST", {
            message: "Password needs 6+ characters, uppercase and lowercase letters."
          });
        }
      }
    })
  },
  user: {
    additionalFields: {
      role: { type: "string", defaultValue: "customer", input: false },
      roleSelected: { type: "boolean", defaultValue: false, input: false },
      isBlocked: { type: "boolean", defaultValue: false, input: false },
      subscriptionPlan: { type: "string", defaultValue: "free", input: false },
      businessName: { type: "string", defaultValue: "", input: false },
      subscriptionExpiresAt: { type: "date", required: false, input: false }
    }
  },
  socialProviders: process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET
    ? { google: {
        clientId: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      } }
    : {},
});

export const clientURL = website;
