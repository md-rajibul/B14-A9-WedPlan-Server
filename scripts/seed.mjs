import "dotenv/config";
import { mongoClient, auth, users, services } from "../db.mjs";

const required = ["MONGODB_URI", "BETTER_AUTH_SECRET", "JWT_SECRET",
  "ADMIN_EMAIL", "ADMIN_PASSWORD", "DEMO_VENDOR_EMAIL", "DEMO_VENDOR_PASSWORD",
  "DEMO_VENDOR_2_EMAIL", "DEMO_VENDOR_2_PASSWORD"];
const missing = required.filter(k => !process.env[k]);
if (missing.length) {
  console.error("Missing .env entries:", missing.join(", "));
  process.exit(1);
}
if ([process.env.ADMIN_PASSWORD, process.env.DEMO_VENDOR_PASSWORD,
     process.env.DEMO_VENDOR_2_PASSWORD].some(p => p.length < 10 || !/[A-Z]/.test(p) || !/[a-z]/.test(p))) {
  console.error("Use passwords of at least 10 characters for seed accounts.");
  process.exit(1);
}
async function ensureAccount(email, password, name, role, businessName="") {
  email = email.trim().toLowerCase();
  if (!email.includes("@")) throw Error("Invalid seed email");
  let u = await users.findOne({ email });
  if (!u) {
    const result = await auth.api.signUpEmail({ body: { email, password, name } });
    if (result?.error) throw Error(result.error.message || "Sign up failed");
    u = await users.findOne({ email });
  }
  if (!u) throw Error("Could not create " + email);
  await users.updateOne({ _id: u._id }, { $set: {
    role, roleSelected: true, isBlocked: false, businessName,
    subscriptionPlan: "free"
  } });
  return { ...u, role, businessName };
}
const sample = [
  ["Timeless Wedding Photography", "Photography & Videography", "Dhaka", 25000,
    "https://images.unsplash.com/photo-1519741497674-611481863552?w=1000"],
  ["Elegant Wedding Venue", "Wedding Venues", "Dhaka", 85000,
    "https://images.unsplash.com/photo-1511795409834-ef04bbd61622?w=1000"],
  ["Dream Floral Decoration", "Decoration & Florist", "Chattogram", 35000,
    "https://images.unsplash.com/photo-1523438885200-e635ba2c371e?w=1000"],
  ["Luxury Wedding Catering", "Catering Services", "Sylhet", 45000,
    "https://images.unsplash.com/photo-1555244162-803834f70033?w=1000"],
  ["Bridal Styling Essentials", "Makeup & Styling", "Dhaka", 12000,
    "https://images.unsplash.com/photo-1583784561105-a674080f391e?w=1000"],
  ["Wedding Fashion Collection", "Wedding Fashion", "Rajshahi", 18000,
    "https://images.unsplash.com/photo-1591221662157-6f62de5508eb?w=1000"],
];
async function main() {
  await mongoClient.connect();
  await ensureAccount(process.env.ADMIN_EMAIL, process.env.ADMIN_PASSWORD,
    "WedPlan Administrator", "admin");
  const v1 = await ensureAccount(process.env.DEMO_VENDOR_EMAIL,
    process.env.DEMO_VENDOR_PASSWORD, "Dream Events", "vendor", "Dream Events");
  const v2 = await ensureAccount(process.env.DEMO_VENDOR_2_EMAIL,
    process.env.DEMO_VENDOR_2_PASSWORD, "Celebration Studio", "vendor", "Celebration Studio");
  for (let i = 0; i < sample.length; i++) {
    const [serviceName, category, location, price, image] = sample[i];
    const vendor = i < 3 ? v1 : v2;
    await services.updateOne({
      vendorId: String(vendor._id), serviceName
    }, { $setOnInsert: {
      serviceName, category, location, price, images: [image],
      description: `Professional ${category.toLowerCase()} service for memorable celebrations. Contact our team to plan a wonderful wedding event.`,
      vendorId: String(vendor._id), vendorName: vendor.businessName,
      status: "approved", isActive: true, createdAt: new Date(), updatedAt: new Date()
    } }, { upsert: true });
  }
  console.log("Admin + 2 free vendors + 6 approved demo services ready.");
  console.log("Passwords remain only in your private .env file.");
}
main().catch(console.error).finally(() => mongoClient.close());
