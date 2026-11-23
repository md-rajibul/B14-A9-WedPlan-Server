import "dotenv/config";
import express from "express";
import cors from "cors";
import jwt from "jsonwebtoken";
import { ObjectId } from "mongodb";
import { toNodeHandler, fromNodeHeaders } from "better-auth/node";
import Stripe from "stripe";
import multer from "multer";
import {
  mongoClient, db, auth, users, services, bookings, transactions, clientURL
} from "./db.mjs";

const app = express();
const PORT = Number(process.env.PORT || 5000);
const stripe = process.env.STRIPE_SECRET_KEY
  ? new Stripe(process.env.STRIPE_SECRET_KEY) : null;

app.disable("x-powered-by");
app.use(cors({ origin: clientURL, credentials: true }));

const asyncRoute = (fn) => (req, res, next) =>
  Promise.resolve(fn(req, res, next)).catch(next);
const asId = (value) =>
  typeof value === "string" && ObjectId.isValid(value) &&
  new ObjectId(value).toString() === value ? new ObjectId(value) : null;
const output = (obj) => obj ? { ...obj, _id: undefined, id: String(obj._id) } : null;
const err = (res, code, message) => res.status(code).json({ error: message });
const owns = (obj, uid) => obj.vendorId === uid || obj.customerId === uid;
const safeRegex = (s) => String(s || "").slice(0, 100).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const isPremium = (u) => u.subscriptionPlan === "premium" &&
  u.subscriptionExpiresAt && new Date(u.subscriptionExpiresAt).getTime() > Date.now();

function subscriptionExpiry(subscription) {
  const seconds = subscription?.items?.data?.[0]?.current_period_end ??
    subscription?.current_period_end;
  return seconds ? new Date(seconds * 1000) : null;
}
async function activatePremium(vendorId, subscriptionId, expiresAt) {
  const vendor = asId(vendorId);
  if (!vendor || !expiresAt) return;
  await users.updateOne(
    { _id: vendor, role: "vendor" },
    { $set: {
      subscriptionPlan: "premium", subscriptionExpiresAt: expiresAt,
      stripeSubscriptionId: subscriptionId
    } }
  );
}

// Stripe raw-body verifier MUST be registered before express.json.
app.post("/api/stripe/webhook", express.raw({ type: "application/json" }),
  asyncRoute(async (req, res) => {
    if (!stripe || !process.env.STRIPE_WEBHOOK_SECRET)
      return err(res, 503, "Stripe webhook not configured");
    let event;
    try {
      event = stripe.webhooks.constructEvent(
        req.body, req.headers["stripe-signature"], process.env.STRIPE_WEBHOOK_SECRET
      );
    } catch {
      return err(res, 400, "Webhook signature verification failed");
    }
    const obj = event.data.object;
    if (event.type === "checkout.session.completed" && obj.mode === "subscription") {
      const vendorId = obj.metadata?.vendorId || obj.client_reference_id;
      if (obj.payment_status === "paid" && vendorId && obj.subscription) {
        const sub = await stripe.subscriptions.retrieve(obj.subscription);
        await activatePremium(vendorId, String(sub.id), subscriptionExpiry(sub));
        await transactions.updateOne({ stripeSessionId: obj.id }, {
          $setOnInsert: {
            vendorId, plan: "premium", amount: obj.amount_total ?? 0,
            currency: obj.currency ?? "usd", status: "paid",
            stripeSessionId: obj.id, stripeSubscriptionId: String(sub.id),
            createdAt: new Date()
          }
        }, { upsert: true });
      }
    }
    if (event.type === "invoice.paid") {
      const subId = obj.parent?.subscription_details?.subscription || obj.subscription;
      if (subId) {
        const sub = await stripe.subscriptions.retrieve(String(subId));
        const vendorId = sub.metadata?.vendorId;
        if (vendorId) {
          await activatePremium(vendorId, sub.id, subscriptionExpiry(sub));
          const invoiceId = String(obj.id);
          await transactions.updateOne({ stripeInvoiceId: invoiceId }, {
            $setOnInsert: {
              vendorId, plan: "premium", amount: obj.amount_paid ?? 0,
              currency: obj.currency ?? "usd", status: "paid",
              stripeInvoiceId: invoiceId, stripeSubscriptionId: sub.id,
              createdAt: new Date()
            }
          }, { upsert: true });
        }
      }
    }
    if (event.type === "customer.subscription.deleted") {
      const vendorId = asId(obj.metadata?.vendorId);
      if (vendorId) await users.updateOne(
        { _id: vendorId, stripeSubscriptionId: obj.id },
        { $set: { subscriptionPlan: "free", subscriptionExpiresAt: new Date() } }
      );
    }
    res.json({ received: true });
  })
);

// Better Auth handler must precede body parsers.
app.all(/^\/api\/auth\/.*$/, toNodeHandler(auth));
app.use(express.json({ limit: "1mb" }));

app.get("/", (req, res) => res.type("text").send("WedPlan Server is Running!"));
app.get("/api/health", asyncRoute(async (req, res) => {
  await db.command({ ping: 1 });
  res.json({ server: "ok", mongodb: "connected" });
}));

// JWT is issued ONLY after server verifies the Better Auth session.
app.get("/api/session/token", asyncRoute(async (req, res) => {
  const session = await auth.api.getSession({ headers: fromNodeHeaders(req.headers) });
  if (!session?.user?.email) return err(res, 401, "Please sign in");
  const user = await users.findOne({ email: session.user.email.toLowerCase() });
  if (!user || user.isBlocked) return err(res, 403, "Account blocked");
  const token = jwt.sign({ sub: String(user._id), email: user.email },
    process.env.JWT_SECRET, { issuer: "wedplan", expiresIn: "15m", algorithm: "HS256" });
  res.json({ token });
}));

async function guard(req, res, next) {
  try {
    const h = req.headers.authorization || "";
    if (!h.startsWith("Bearer ")) return err(res, 401, "Sign in required");
    const payload = jwt.verify(h.slice(7), process.env.JWT_SECRET,
      { issuer: "wedplan", algorithms: ["HS256"] });
    const uid = asId(payload.sub);
    if (!uid) return err(res, 401, "Invalid token");
    const user = await users.findOne({ _id: uid, email: payload.email });
    if (!user || user.isBlocked) return err(res, 403, "Account blocked or unavailable");
    req.user = user;
    req.userId = String(user._id);
    next();
  } catch {
    return err(res, 401, "Invalid or expired token");
  }
}
const role = (...allowed) => (req, res, next) =>
  allowed.includes(req.user.role) ? next() : err(res, 403, "Role not permitted");
const publicUser = (u) => ({
  id: String(u._id), name: u.name, email: u.email, image: u.image || "",
  role: u.role || "customer", roleSelected: Boolean(u.roleSelected),
  businessName: u.businessName || "", isBlocked: Boolean(u.isBlocked),
  subscriptionPlan: isPremium(u) ? "premium" : "free",
  subscriptionExpiresAt: u.subscriptionExpiresAt ?? null
});

app.get("/api/me", guard, (req, res) => res.json(publicUser(req.user)));

app.post("/api/profile/role", guard, asyncRoute(async (req, res) => {
  if (!["customer", "vendor"].includes(req.body.role))
    return err(res, 400, "Choose customer or vendor");
  const businessName = String(req.body.businessName || "").trim().slice(0, 100);
  if (req.body.role === "vendor" && !businessName)
    return err(res, 400, "Vendor business name is required");
  const updated = await users.updateOne({
    _id: req.user._id, roleSelected: { $ne: true }, role: { $ne: "admin" }
  }, { $set: { role: req.body.role, businessName, roleSelected: true } });
  if (!updated.modifiedCount) return err(res, 409, "Role already selected");
  res.json({ success: true });
}));

app.patch("/api/profile", guard, asyncRoute(async (req, res) => {
  const name = String(req.body.name || "").trim().slice(0, 100);
  if (name.length < 2) return err(res, 400, "Name is required");
  const fields = { name };
  if (typeof req.body.image === "string") {
    if (req.body.image && !/^https:\/\//i.test(req.body.image))
      return err(res, 400, "Invalid image URL");
    fields.image = req.body.image;
  }
  if (req.user.role === "vendor") {
    fields.businessName = String(req.body.businessName || req.user.businessName || "")
      .trim().slice(0, 100);
  }
  await users.updateOne({ _id: req.user._id }, { $set: fields });
  res.json({ success: true });
}));

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (_req, file, cb) => cb(null,
    ["image/png", "image/jpeg", "image/webp"].includes(file.mimetype))
});
app.post("/api/upload", guard, upload.single("image"), asyncRoute(async (req, res) => {
  if (!req.file) return err(res, 400, "Select a JPG, PNG or WebP image under 5MB");
  if (!process.env.IMGBB_API_KEY) return err(res, 503, "Image hosting is not configured");
  const form = new URLSearchParams({ image: req.file.buffer.toString("base64") });
  const result = await fetch(
    `https://api.imgbb.com/1/upload?key=${encodeURIComponent(process.env.IMGBB_API_KEY)}`,
    { method: "POST", body: form }
  );
  const data = await result.json();
  if (!result.ok || !data.success || !data.data?.url)
    return err(res, 502, "Image upload failed");
  res.json({ url: data.data.url });
}));

const categories = new Set([
  "Photography & Videography", "Wedding Venues", "Decoration & Florist",
  "Catering Services", "Makeup & Styling", "Wedding Fashion"
]);
function validateService(body) {
  const serviceName = String(body.serviceName || "").trim().slice(0, 120);
  const category = String(body.category || "");
  const description = String(body.description || "").trim().slice(0, 3000);
  const location = String(body.location || "").trim().slice(0, 100);
  const price = Number(body.price);
  const images = Array.isArray(body.images) ? body.images.filter(x =>
    typeof x === "string" && /^https:\/\//i.test(x)).slice(0, 6) : [];
  if (!serviceName || !categories.has(category) || description.length < 10 ||
      !location || !Number.isFinite(price) || price <= 0 || !images.length)
    throw Object.assign(new Error("Complete all service fields and upload an image"),
      { status: 400 });
  return { serviceName, category, description, location, price, images };
}

app.get("/api/services", asyncRoute(async (req, res) => {
  const filter = { status: "approved", isActive: true };
  if (req.query.search) filter.serviceName = {
    $regex: safeRegex(req.query.search), $options: "i"
  };
  if (categories.has(req.query.category)) filter.category = req.query.category;
  if (req.query.location) filter.location = {
    $regex: safeRegex(req.query.location), $options: "i"
  };
  const order = req.query.sort === "asc" ? { price: 1 } :
    req.query.sort === "desc" ? { price: -1 } : { createdAt: -1 };
  const list = await services.find(filter).sort(order).limit(100).toArray();
  res.json(list.map(output));
}));

app.get("/api/services/:id", guard, asyncRoute(async (req, res) => {
  const _id = asId(req.params.id);
  if (!_id) return err(res, 400, "Invalid service ID");
  const s = await services.findOne({ _id });
  if (!s) return err(res, 404, "Service not found");
  if (s.status !== "approved" || !s.isActive) {
    if (s.vendorId !== req.userId && req.user.role !== "admin")
      return err(res, 403, "Service not available");
  }
  res.json(output(s));
}));

app.get("/api/vendor/services", guard, role("vendor"), asyncRoute(async (req, res) => {
  const list = await services.find({ vendorId: req.userId })
    .sort({ createdAt: -1 }).toArray();
  res.json(list.map(output));
}));
app.post("/api/services", guard, role("vendor"), asyncRoute(async (req, res) => {
  const data = validateService(req.body);
  const result = await services.insertOne({
    ...data, vendorId: req.userId, vendorName: req.user.businessName || req.user.name,
    status: "pending", isActive: true, createdAt: new Date(), updatedAt: new Date()
  });
  res.status(201).json({ id: String(result.insertedId), status: "pending" });
}));
app.patch("/api/services/:id", guard, role("vendor"), asyncRoute(async (req, res) => {
  const _id = asId(req.params.id);
  if (!_id) return err(res, 400, "Invalid service ID");
  const data = validateService(req.body);
  const updated = await services.updateOne({ _id, vendorId: req.userId },
    { $set: { ...data, status: "pending", updatedAt: new Date() } });
  if (!updated.matchedCount) return err(res, 404, "Service not found");
  res.json({ success: true, status: "pending" });
}));
app.patch("/api/services/:id/availability", guard, role("vendor"),
  asyncRoute(async (req, res) => {
    const _id = asId(req.params.id);
    if (!_id || typeof req.body.isActive !== "boolean")
      return err(res, 400, "Invalid service or availability");
    if (req.body.isActive && !isPremium(req.user)) {
      const active = await services.countDocuments({
        vendorId: req.userId, status: "approved", isActive: true, _id: { $ne: _id }
      });
      if (active >= 3) return err(res, 409, "Free vendors may have 3 active services");
    }
    const updated = await services.updateOne({ _id, vendorId: req.userId },
      { $set: { isActive: req.body.isActive, updatedAt: new Date() } });
    if (!updated.matchedCount) return err(res, 404, "Service not found");
    res.json({ success: true });
  }));
app.delete("/api/services/:id", guard, role("vendor", "admin"),
  asyncRoute(async (req, res) => {
    const _id = asId(req.params.id);
    if (!_id) return err(res, 400, "Invalid ID");
    const filter = { _id };
    if (req.user.role !== "admin") filter.vendorId = req.userId;
    const activeBookings = await bookings.countDocuments({
      serviceId: String(_id), status: "accepted"
    });
    if (activeBookings) return err(res, 409, "An accepted booking exists");
    const result = await services.deleteOne(filter);
    if (!result.deletedCount) return err(res, 404, "Service not found");
    res.json({ success: true });
  }));

app.post("/api/bookings", guard, role("customer"), asyncRoute(async (req, res) => {
  const sid = asId(req.body.serviceId);
  const date = String(req.body.eventDate || "");
  const location = String(req.body.eventLocation || "").trim().slice(0, 150);
  const msg = String(req.body.message || "").trim().slice(0, 1000);
  if (!sid || !/^\d{4}-\d{2}-\d{2}$/.test(date) ||
      !Number.isFinite(Date.parse(date)) || date < new Date().toISOString().slice(0,10) ||
      !location) return err(res, 400, "Valid future event date and location required");
  const svc = await services.findOne({ _id: sid, status: "approved", isActive: true });
  if (!svc) return err(res, 404, "Service unavailable");
  if (svc.vendorId === req.userId) return err(res, 403, "You cannot book your own service");
  const key = `${req.userId}:${sid}:${date}`;
  try {
    const result = await bookings.insertOne({
      bookingKey: key, serviceId: String(sid), vendorId: svc.vendorId,
      customerId: req.userId, customerName: req.user.name, customerEmail: req.user.email,
      serviceName: svc.serviceName, serviceImage: svc.images[0], vendorName: svc.vendorName,
      eventDate: date, eventLocation: location, message: msg,
      status: "pending", createdAt: new Date()
    });
    res.status(201).json({ id: String(result.insertedId) });
  } catch (e) {
    if (e.code === 11000) return err(res, 409, "Duplicate active booking");
    throw e;
  }
}));
app.get("/api/customer/bookings", guard, role("customer"), asyncRoute(async (req, res) => {
  const list = await bookings.find({ customerId: req.userId })
    .sort({ createdAt: -1 }).toArray();
  res.json(list.map(output));
}));
app.patch("/api/customer/bookings/:id/cancel", guard, role("customer"),
  asyncRoute(async (req, res) => {
    const _id = asId(req.params.id);
    if (!_id) return err(res, 400, "Invalid booking ID");
    const result = await bookings.updateOne({
      _id, customerId: req.userId, status: "pending"
    }, { $set: { status: "cancelled", updatedAt: new Date() }, $unset: { bookingKey: "" } });
    if (!result.modifiedCount) return err(res, 409, "Booking cannot be cancelled");
    res.json({ success: true });
  }));
app.get("/api/vendor/bookings", guard, role("vendor"), asyncRoute(async (req, res) => {
  const list = await bookings.find({ vendorId: req.userId })
    .sort({ createdAt: -1 }).toArray();
  res.json(list.map(output));
}));
app.patch("/api/vendor/bookings/:id/decision", guard, role("vendor"),
  asyncRoute(async (req, res) => {
    const _id = asId(req.params.id);
    const decision = req.body.status;
    if (!_id || !["accepted", "rejected"].includes(decision))
      return err(res, 400, "Invalid booking decision");
    const change = { $set: { status: decision, updatedAt: new Date() } };
    if (decision === "rejected") change.$unset = { bookingKey: "" };
    const result = await bookings.updateOne({
      _id, vendorId: req.userId, status: "pending"
    }, change);
    if (!result.modifiedCount) return err(res, 409, "Booking already processed");
    res.json({ success: true });
  }));

app.get("/api/vendor/overview", guard, role("vendor"), asyncRoute(async (req, res) => {
  const vendorId = req.userId;
  const [totalServices, activeServices, pendingBookings, acceptedBookings] =
    await Promise.all([
      services.countDocuments({ vendorId }),
      services.countDocuments({ vendorId, status: "approved", isActive: true }),
      bookings.countDocuments({ vendorId, status: "pending" }),
      bookings.countDocuments({ vendorId, status: "accepted" })
    ]);
  res.json({
    totalServices, activeServices, pendingBookings, acceptedBookings,
    subscriptionPlan: isPremium(req.user) ? "premium" : "free"
  });
}));
app.get("/api/customer/overview", guard, role("customer"), asyncRoute(async (req, res) => {
  const customerId = req.userId;
  const [totalBookings, pendingBookings, acceptedBookings, rejectedBookings] =
    await Promise.all([
      bookings.countDocuments({ customerId }),
      bookings.countDocuments({ customerId, status: "pending" }),
      bookings.countDocuments({ customerId, status: "accepted" }),
      bookings.countDocuments({ customerId, status: "rejected" })
    ]);
  res.json({ totalBookings, pendingBookings, acceptedBookings, rejectedBookings });
}));

app.get("/api/admin/overview", guard, role("admin"), asyncRoute(async (req, res) => {
  const [totalUsers, totalVendors, totalCustomers, totalServices,
    pendingServices, totalTransactions] = await Promise.all([
      users.countDocuments(), users.countDocuments({ role: "vendor" }),
      users.countDocuments({ role: "customer" }), services.countDocuments(),
      services.countDocuments({ status: "pending" }), transactions.countDocuments()
    ]);
  res.json({ totalUsers, totalVendors, totalCustomers, totalServices,
    pendingServices, totalTransactions });
}));
app.get("/api/admin/users", guard, role("admin"), asyncRoute(async (req, res) => {
  const filter = {};
  if (["customer", "vendor", "admin"].includes(req.query.role))
    filter.role = req.query.role;
  if (req.query.search) filter.$or = [
    { name: { $regex: safeRegex(req.query.search), $options: "i" } },
    { email: { $regex: safeRegex(req.query.search), $options: "i" } }
  ];
  const list = await users.find(filter, {
    projection: { name: 1, email: 1, role: 1, image: 1,
      isBlocked: 1, subscriptionPlan: 1, businessName: 1 }
  }).limit(200).toArray();
  res.json(list.map(output));
}));
app.patch("/api/admin/users/:id/block", guard, role("admin"),
  asyncRoute(async (req, res) => {
    const _id = asId(req.params.id);
    if (!_id || _id.equals(req.user._id) || typeof req.body.isBlocked !== "boolean")
      return err(res, 400, "Invalid request");
    const result = await users.updateOne({ _id, role: { $ne: "admin" } },
      { $set: { isBlocked: req.body.isBlocked } });
    if (!result.matchedCount) return err(res, 404, "User not found");
    res.json({ success: true });
  }));
app.get("/api/admin/services", guard, role("admin"), asyncRoute(async (req, res) => {
  const filter = {};
  if (["pending", "approved", "rejected"].includes(req.query.status))
    filter.status = req.query.status;
  const list = await services.find(filter).sort({ createdAt: -1 }).limit(200).toArray();
  res.json(list.map(output));
}));
app.patch("/api/admin/services/:id/review", guard, role("admin"),
  asyncRoute(async (req, res) => {
    const _id = asId(req.params.id);
    const status = req.body.status;
    if (!_id || !["approved", "rejected"].includes(status))
      return err(res, 400, "Invalid service or status");
    const svc = await services.findOne({ _id });
    if (!svc) return err(res, 404, "Service not found");
    if (status === "approved" && svc.isActive) {
      const vendor = await users.findOne({ _id: asId(svc.vendorId) });
      if (!vendor) return err(res, 404, "Vendor missing");
      if (!isPremium(vendor)) {
        const count = await services.countDocuments({
          vendorId: svc.vendorId, status: "approved", isActive: true, _id: { $ne: _id }
        });
        if (count >= 3) return err(res, 409, "Free vendor limit: 3 active services");
      }
    }
    await services.updateOne({ _id }, { $set: { status, updatedAt: new Date() } });
    res.json({ success: true });
  }));
app.patch("/api/admin/services/:id/status", guard, role("admin"),
  asyncRoute(async (req, res) => {
    const _id = asId(req.params.id);
    if (!_id || typeof req.body.isActive !== "boolean")
      return err(res, 400, "Invalid availability");
    const svc = await services.findOne({ _id });
    if (!svc) return err(res, 404, "Service not found");
    if (req.body.isActive && svc.status === "approved") {
      const vendor = await users.findOne({ _id: asId(svc.vendorId) });
      if (!vendor) return err(res, 404, "Vendor not found");
      if (!isPremium(vendor)) {
        const count = await services.countDocuments({
          vendorId: svc.vendorId, status: "approved", isActive: true, _id: { $ne: _id }
        });
        if (count >= 3) return err(res, 409, "Free vendor limit reached");
      }
    }
    await services.updateOne({ _id }, { $set: {
      isActive: req.body.isActive, updatedAt: new Date()
    } });
    res.json({ success: true });
  }));
app.get("/api/admin/transactions", guard, role("admin"), asyncRoute(async (req, res) => {
  const list = await transactions.find().sort({ createdAt: -1 }).limit(200).toArray();
  res.json(list.map(output));
}));

app.post("/api/stripe/checkout", guard, role("vendor"), asyncRoute(async (req, res) => {
  if (!stripe || !process.env.STRIPE_PRICE_ID)
    return err(res, 503, "Stripe Test Mode is not configured");
  if (isPremium(req.user)) return err(res, 409, "Already premium");
  const session = await stripe.checkout.sessions.create({
    mode: "subscription",
    line_items: [{ price: process.env.STRIPE_PRICE_ID, quantity: 1 }],
    client_reference_id: req.userId,
    metadata: { vendorId: req.userId },
    subscription_data: { metadata: { vendorId: req.userId } },
    success_url: `${clientURL}/payment/success`,
    cancel_url: `${clientURL}/payment/cancel`
  });
  res.json({ url: session.url });
}));

app.use((req, res) => err(res, 404, "Route not found"));
app.use((error, req, res, next) => {
  console.error(error);
  if (error.code === "LIMIT_FILE_SIZE") return err(res, 400, "Image too large (max 5MB)");
  res.status(error.status || 500).json({
    error: error.status && error.status < 500 ? error.message : "Server error"
  });
});

async function start() {
  for (const name of ["MONGODB_URI", "BETTER_AUTH_SECRET", "JWT_SECRET"]) {
    if (!process.env[name]) throw Error(`${name} is missing from .env`);
  }
  await mongoClient.connect();
  await db.command({ ping: 1 });
  await bookings.createIndex(
    { bookingKey: 1 }, { unique: true, partialFilterExpression: { bookingKey: { $type: "string" } } }
  );
  
const existingIndexes = await transactions.indexes();
const oldIndex = existingIndexes.find(
  (index) => index.name === "stripeSessionId_1"
);

if (
  oldIndex &&
  oldIndex.key?.stripeSessionId === 1 &&
  oldIndex.unique === true &&
  oldIndex.sparse !== true
) {
  await transactions.dropIndex("stripeSessionId_1");
}

await transactions.createIndex(
  { stripeSessionId: 1 },
  { unique: true, sparse: true }
);

  await transactions.createIndex({ stripeInvoiceId: 1 }, { unique: true, sparse: true });
  await services.createIndex({ status: 1, isActive: 1, category: 1, createdAt: -1 });
  app.listen(PORT, () => console.log(`WedPlan Server running on port ${PORT}\nMongoDB connected`));
}
start().catch(e => { console.error("Startup failed:", e.message); process.exit(1); });
