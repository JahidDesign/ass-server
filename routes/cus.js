const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { ObjectId } = require("mongodb");
const { getCustomerCollection } = require("../db");
const verifyFirebaseToken = require("../verifyFirebaseToken");

const router = express.Router();
const JWT_SECRET = process.env.JWT_SECRET || "super_secret_key";
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || "7d";

// ===== Helper: Sign JWT =====
function signToken(user) {
  return jwt.sign(
    { id: user._id, email: user.email }, // role removed
    JWT_SECRET,
    { expiresIn: JWT_EXPIRES_IN }
  );
}

// ===== Helper: Remove password =====
function sanitizeUser(user) {
  if (!user) return null;
  const { password, ...rest } = user;
  return rest;
}

// ===== CREATE / REGISTER =====
router.post("/", async (req, res) => {
  try {
    const { uid, name, email, password, photo, phone, status } = req.body;
    if (!uid || !name || !email || !password)
      return res.status(400).json({ error: "Missing required fields." });

    const customers = await getCustomerCollection();
    const existing = await customers.findOne({ email });
    if (existing) return res.status(409).json({ error: "User already exists." });

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = {
      uid,
      name,
      email,
      password: hashedPassword,
      photo: photo || "",
      phone: phone || "",
      status: status || "active",
      createdAt: new Date(),
    };

    const result = await customers.insertOne(newUser);
    res.status(201).json({ message: "User created", user: sanitizeUser({ _id: result.insertedId, ...newUser }) });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ===== LOGIN =====
router.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: "Email and password required." });

    const customers = await getCustomerCollection();
    const user = await customers.findOne({ email });
    if (!user || !user.password) return res.status(401).json({ error: "Invalid credentials." });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ error: "Invalid password." });

    const token = signToken(user);
    res.json({ user: sanitizeUser(user), token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ===== FIREBASE LOGIN =====
router.post("/firebase-login", verifyFirebaseToken, async (req, res) => {
  try {
    const { uid, email, name, picture, phone } = req.firebaseUser;

    const customers = await getCustomerCollection();
    let user = await customers.findOne({ email });

    if (!user) {
      const newUser = {
        uid,
        name: name || "Firebase User",
        email,
        photo: picture || "",
        phone: phone || "",
        status: "active",
        createdAt: new Date(),
      };
      const result = await customers.insertOne(newUser);
      user = { _id: result.insertedId, ...newUser };
    }

    const token = signToken(user);
    res.json({ user: sanitizeUser(user), token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ===== READ ALL USERS =====
router.get("/", async (req, res) => {
  try {
    const customers = await getCustomerCollection();
    const users = await customers.find({}).toArray();
    res.json(users.map(sanitizeUser));
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ===== READ SINGLE USER BY ID =====
router.get("/:id", async (req, res) => {
  try {
    const customers = await getCustomerCollection();
    const user = await customers.findOne({ _id: new ObjectId(req.params.id) });
    if (!user) return res.status(404).json({ error: "User not found" });
    res.json(sanitizeUser(user));
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ===== UPDATE USER =====
router.put("/:id", async (req, res) => {
  try {
    const { name, email, password, photo, phone, status } = req.body;
    const updateData = {};
    if (name) updateData.name = name;
    if (email) updateData.email = email;
    if (photo) updateData.photo = photo;
    if (phone) updateData.phone = phone;
    if (status) updateData.status = status;
    if (password) updateData.password = await bcrypt.hash(password, 10);

    const customers = await getCustomerCollection();
    const result = await customers.findOneAndUpdate(
      { _id: new ObjectId(req.params.id) },
      { $set: updateData },
      { returnDocument: "after" }
    );

    if (!result.value) return res.status(404).json({ error: "User not found" });
    res.json({ message: "User updated", user: sanitizeUser(result.value) });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ===== DELETE USER =====
router.delete("/:id", async (req, res) => {
  try {
    const customers = await getCustomerCollection();
    const result = await customers.deleteOne({ _id: new ObjectId(req.params.id) });
    if (result.deletedCount === 0) return res.status(404).json({ error: "User not found" });
    res.json({ message: "User deleted" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Internal server error" });
  }
});

module.exports = router;
