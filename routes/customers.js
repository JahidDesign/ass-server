const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { ObjectId } = require("mongodb");
const { getCustomerCollection } = require("../db");
const router = express.Router();

const JWT_SECRET = process.env.JWT_SECRET || "4adb4dadd6fcf937016a719b1ec35b9dae4d31534ec753fddb7e9c7b7c5c02cbbac37f1b2b933594d669dcfbb25757bbdef5e6bcca5af71d2335b8ae777a9e7e";
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || "7d";

// Sign JWT
function signToken(user) {
  return jwt.sign(
    { id: user._id, email: user.email, role: user.role },
    JWT_SECRET,
    { expiresIn: JWT_EXPIRES_IN }
  );
}

// Remove password
function sanitizeUser(user) {
  if (!user) return null;
  const { password, ...rest } = user;
  return rest;
}

// ===== CREATE USER =====
router.post("/", async (req, res) => {
  try {
    const { uid, name, email, password, photo, phone, role, status } = req.body;
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
      role: role || "customer",
      status: status || "active",
      createdAt: new Date(),
    };

    const result = await customers.insertOne(newUser);
    res.status(201).json({ message: "User created", id: result.insertedId });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ===== LOGIN USER =====
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

// ===== GOOGLE LOGIN =====
router.post("/google-login", async (req, res) => {
  try {
    const { uid, email, name, photo } = req.body;
    if (!uid || !email) return res.status(400).json({ error: "UID and email required." });

    const customers = await getCustomerCollection();
    let user = await customers.findOne({ email });

    if (!user) {
      const newUser = {
        uid,
        name: name || "Google User",
        email,
        photo: photo || "",
        phone: "",
        role: "customer",
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

// ===== READ ALL =====
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

// ===== READ ONE =====
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
    const { name, email, password, photo, phone, role, status } = req.body;
    const updateData = {};
    if (name) updateData.name = name;
    if (email) updateData.email = email;
    if (photo) updateData.photo = photo;
    if (phone) updateData.phone = phone;
    if (role) updateData.role = role;
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
