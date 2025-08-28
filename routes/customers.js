// routes/customers.js
const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { ObjectId } = require("mongodb");
const { getCustomersCollection } = require("../db");
const verifyFirebaseToken = require("../middleware/verifyFirebaseToken");
require("dotenv").config();

const router = express.Router();
const JWT_EXPIRES = "7d";
const JWT_SECRET = process.env.JWT_SECRET || "4adb4dadd6fcf937016a719b1ec35b9dae4d31534ec753fddb7e9c7b7c5c02cbbac37f1b2b933594d669dcfbb25757bbdef5e6bcca5af71d2335b8ae777a9e7e";

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

// ===== GET All Customers (Protected) =====
router.get("/", verifyToken, async (req, res) => {
  try {
    const customers = await getCustomersCollection().find().project({ password: 0 }).toArray();
    res.json(customers);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to fetch customers" });
  }
});

// ===== GET Customer By ID (Protected) =====
router.get("/:id", verifyToken, async (req, res) => {
  try {
    const customer = await getCustomersCollection().findOne(
      { _id: new ObjectId(req.params.id) },
      { projection: { password: 0 } }
    );
    if (!customer) return res.status(404).json({ error: "Customer not found" });
    res.json(customer);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to fetch customer" });
  }
});

// ===== REGISTER Customer (Email/Password) =====
router.post("/", async (req, res) => {
  try {
    const { fullName, email, password, phone, firebaseUid, photo } = req.body;
    if (!email || !password) return res.status(400).json({ error: "Email & password required" });

    const coll = getCustomersCollection();
    const existing = await coll.findOne({ email });
    if (existing) return res.status(409).json({ error: "Email already registered" });

    const hashedPassword = await bcrypt.hash(password, 10);
    const newCustomer = {
      fullName,
      email,
      password: hashedPassword,
      phone: phone || "",
      firebaseUid: firebaseUid || "",
      photo: photo || "",
      createdAt: new Date(),
    };

    const result = await coll.insertOne(newCustomer);

    const token = jwt.sign({ id: result.insertedId, email }, JWT_SECRET, { expiresIn: JWT_EXPIRES });
    res.status(201).json({ message: "Customer created", token, customer: { id: result.insertedId, fullName, email, phone, photo } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Registration failed" });
  }
});

// ===== LOGIN Customer (Email/Password) =====
router.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const coll = getCustomersCollection();
    const customer = await coll.findOne({ email });
    if (!customer) return res.status(401).json({ error: "Invalid credentials" });

    const match = await bcrypt.compare(password, customer.password);
    if (!match) return res.status(401).json({ error: "Invalid credentials" });

    const token = jwt.sign({ id: customer._id, email: customer.email }, JWT_SECRET, { expiresIn: JWT_EXPIRES });
    const { password: pw, ...rest } = customer;
    res.json({ token, customer: rest });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Login failed" });
  }
});

// ===== FIREBASE LOGIN =====
router.post("/firebase-login", verifyFirebaseToken, async (req, res) => {
  try {
    const { uid, email, name, picture, phone_number } = req.firebaseUser;
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

    const token = jwt.sign({ id: customer._id, email: customer.email }, JWT_SECRET, { expiresIn: JWT_EXPIRES });
    res.json({ token, customer });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Firebase login failed" });
  }
});

// ===== UPDATE Customer (Protected) =====
router.put("/:id", verifyToken, async (req, res) => {
  try {
    const { fullName, phone, photo, password } = req.body;
    const update = {};
    if (fullName) update.fullName = fullName;
    if (phone) update.phone = phone;
    if (photo) update.photo = photo;
    if (password) update.password = await bcrypt.hash(password, 10);
    update.updatedAt = new Date();

    const coll = getCustomersCollection();
    const result = await coll.findOneAndUpdate(
      { _id: new ObjectId(req.params.id) },
      { $set: update },
      { returnDocument: "after" }
    );
    if (!result.value) return res.status(404).json({ error: "Customer not found" });
    const { password: pw, ...rest } = result.value;
    res.json({ message: "Customer updated", customer: rest });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Update failed" });
  }
});

// ===== DELETE Customer (Protected) =====
router.delete("/:id", verifyToken, async (req, res) => {
  try {
    const coll = getCustomersCollection();
    const result = await coll.deleteOne({ _id: new ObjectId(req.params.id) });
    if (result.deletedCount === 0) return res.status(404).json({ error: "Customer not found" });
    res.json({ message: "Customer deleted" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Delete failed" });
  }
});

module.exports = router;
