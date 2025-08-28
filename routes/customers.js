// routes/customers.js
const express = require("express");
const { ObjectId } = require("mongodb");
const jwt = require("jsonwebtoken");
const { getCustomersCollection } = require("../db");

const router = express.Router();

// JWT secret (better to store in .env)
const JWT_SECRET = process.env.JWT_SECRET || "4adb4dadd6fcf937016a719b1ec35b9dae4d31534ec753fddb7e9c7b7c5c02cbbac37f1b2b933594d669dcfbb25757bbdef5e6bcca5af71d2335b8ae777a9e7e";

/**
 * @route   GET /customers
 * @desc    Get all customers
 */
router.get("/", async (req, res) => {
  try {
    const customers = await getCustomersCollection().find().toArray();
    res.json(customers);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

/**
 * @route   GET /customers/:id
 * @desc    Get single customer by ID
 */
router.get("/:id", async (req, res) => {
  try {
    const customer = await getCustomersCollection().findOne({
      _id: new ObjectId(req.params.id),
    });
    if (!customer) {
      return res.status(404).json({ error: "Customer not found" });
    }
    res.json(customer);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

/**
 * @route   POST /customers
 * @desc    Register a new customer
 */
router.post("/", async (req, res) => {
  try {
    const { fullName, email, password, phone, firebaseUid } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: "Email & password required" });
    }

    // check if email exists
    const existing = await getCustomersCollection().findOne({ email });
    if (existing) {
      return res.status(400).json({ error: "Email already registered" });
    }

    const newCustomer = {
      fullName,
      email,
      password, // ⚠️ (for demo only, should hash with bcrypt)
      phone,
      firebaseUid,
      createdAt: new Date(),
    };

    const result = await getCustomersCollection().insertOne(newCustomer);

    const token = jwt.sign({ id: result.insertedId }, JWT_SECRET, {
      expiresIn: "7d",
    });

    res.status(201).json({ token, customer: newCustomer });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

/**
 * @route   POST /customers/login
 * @desc    Login with email + password
 */
router.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const customer = await getCustomersCollection().findOne({ email });

    if (!customer || customer.password !== password) {
      return res.status(401).json({ error: "Invalid email or password" });
    }

    const token = jwt.sign({ id: customer._id }, JWT_SECRET, {
      expiresIn: "7d",
    });

    res.json({ token, customer });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

/**
 * @route   DELETE /customers/:id
 * @desc    Delete a customer
 */
router.delete("/:id", async (req, res) => {
  try {
    const result = await getCustomersCollection().deleteOne({
      _id: new ObjectId(req.params.id),
    });

    if (result.deletedCount === 0) {
      return res.status(404).json({ error: "Customer not found" });
    }

    res.json({ message: "Customer deleted" });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

module.exports = router;
