// routes/customers.js
const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { ObjectId } = require("mongodb");
const { getCustomersCollection } = require("../db");
const verifyFirebaseToken = require("../middleware/auth"); // Firebase middleware
require("dotenv").config();

const router = express.Router();

const JWT_SECRET = process.env.JWT_SECRET || "your_default_jwt_secret";
const JWT_EXPIRES = "7d";

// ===== JWT Middleware =====
const verifyToken = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Unauthorized: No token" });
  }
  const token = authHeader.split(" ")[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ error: "Unauthorized: Invalid token" });
  }
};

// ===== ObjectId Validation =====
const isValidObjectId = (id) =>
  ObjectId.isValid(id) && String(new ObjectId(id)) === id;

// ===== GET All Customers (Protected) =====
router.get("/", verifyToken, async (req, res) => {
  try {
    const customers = await getCustomersCollection()
      .find()
      .project({ password: 0 })
      .toArray();
    res.json(customers);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to fetch customers" });
  }
});

// ===== GET Customer By ID (Protected) =====
router.get("/:id", verifyToken, async (req, res) => {
  const { id } = req.params;
  if (!isValidObjectId(id))
    return res.status(400).json({ error: "Invalid customer ID" });

  try {
    const customer = await getCustomersCollection().findOne(
      { _id: new ObjectId(id) },
      { projection: { password: 0 } }
    );
    if (!customer) return res.status(404).json({ error: "Customer not found" });
    res.json(customer);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to fetch customer" });
  }
});

// ===== REGISTER Customer =====
router.post("/", async (req, res) => {
  try {
    const { fullName, email, password, phone, firebaseUid, photo } = req.body;

    if (!email) return res.status(400).json({ error: "Email is required" });
    if (!password && !firebaseUid) {
      return res.status(400).json({ error: "Password required for email signups" });
    }

    const coll = getCustomersCollection();
    const existing = await coll.findOne({ email });
    if (existing) return res.status(409).json({ error: "Email already registered" });

    const hashedPassword = password ? await bcrypt.hash(password, 10) : null;

    const newCustomer = {
      fullName: fullName || "User",
      email,
      password: hashedPassword,
      phone: phone || "",
      firebaseUid: firebaseUid || "",
      photo: photo || "",
      createdAt: new Date(),
    };

    const result = await coll.insertOne(newCustomer);

    const token = jwt.sign({ id: result.insertedId, email }, JWT_SECRET, {
      expiresIn: JWT_EXPIRES,
    });

    res.status(201).json({
      message: "Customer created",
      token,
      customer: { id: result.insertedId, fullName, email, phone, photo },
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Registration failed" });
  }
});

// ===== LOGIN Customer =====
router.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const coll = getCustomersCollection();
    const customer = await coll.findOne({ email });

    if (!customer) return res.status(401).json({ error: "Invalid credentials" });

    if (!customer.password) {
      return res.status(401).json({ error: "Please login with Google" });
    }

    const match = await bcrypt.compare(password, customer.password);
    if (!match) return res.status(401).json({ error: "Invalid credentials" });

    const token = jwt.sign({ id: customer._id, email: customer.email }, JWT_SECRET, {
      expiresIn: JWT_EXPIRES,
    });

    const { password: pw, ...rest } = customer;
    res.json({ token, customer: rest });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Login failed" });
  }
});

// ===== FIREBASE / GOOGLE LOGIN =====
router.post("/firebase-login", verifyFirebaseToken, async (req, res) => {
  try {
    const { uid, email, name, picture, phone_number } = req.user;
    const coll = getCustomersCollection();

    let customer = await coll.findOne({ email });
    if (!customer) {
      const newCustomer = {
        firebaseUid: uid,
        fullName: name || "Firebase User",
        email,
        photo: picture || "",
        phone: phone_number || "",
        createdAt: new Date(),
      };
      const result = await coll.insertOne(newCustomer);
      customer = { _id: result.insertedId, ...newCustomer };
    }

    const token = jwt.sign({ id: customer._id, email: customer.email }, JWT_SECRET, {
      expiresIn: JWT_EXPIRES,
    });

    res.json({ token, customer });
  } catch (err) {
    console.error("Firebase login error:", err);
    res.status(500).json({ error: "Firebase login failed" });
  }
});

module.exports = router;
