
require("dotenv").config();

const express = require("express");
const cors = require("cors");
const { MongoClient } = require("mongodb");

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors({
  origin: process.env.CLIENT_URL || "http://localhost:3000",
  credentials: true
}));

app.use(express.json());

let db = null;

// Home route
app.get("/", (req, res) => {
  res.send("WedPlan Server is Running!");
});

// Health check
app.get("/api/health", (req, res) => {
  res.json({
    server: "ok",
    database: db ? "connected" : "not connected"
  });
});

// Public approved services
app.get("/api/services", async (req, res) => {
  try {
    if (!db) {
      return res.status(503).json({
        error: "Database is not connected"
      });
    }

    const services = await db.collection("services")
      .find({ status: "approved", isActive: true })
      .limit(50)
      .toArray();

    res.json(services);
  } catch (error) {
    res.status(500).json({
      error: "Unable to load services"
    });
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`WedPlan Server running on port ${PORT}`);
});

// Connect MongoDB when configured
if (process.env.MONGODB_URI) {
  const client = new MongoClient(process.env.MONGODB_URI);

  client.connect()
    .then(() => {
      db = client.db("wedplan");
      console.log("MongoDB Connected Successfully");
    })
    .catch((error) => {
      console.error("MongoDB Connection Failed:", error.message);
    });
}
