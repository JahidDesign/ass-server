// customers.auth.router.js
// Fresh, fixed & optimized auth router with email+password and Firebase login
// NOTE: install deps -> npm i express bcryptjs jsonwebtoken express-rate-limit validator dotenv

const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { ObjectId } = require("mongodb");
const rateLimit = require("express-rate-limit");
const validator = require("validator");
require("dotenv").config();

const { getCustomersCollection } = require("../db");
const verifyFirebaseToken = require("../middleware/auth");

const router = express.Router();

// ===== Security & JWT Config =====
// ⚠️ In production, ALWAYS set these in your .env
const JWT_SECRET = process.env.JWT_SECRET; // e.g., a 256-bit random string
const REFRESH_TOKEN_SECRET = process.env.REFRESH_TOKEN_SECRET; // separate from JWT_SECRET

if (!JWT_SECRET || !REFRESH_TOKEN_SECRET) {
  console.warn(
    "[WARN] JWT_SECRET or REFRESH_TOKEN_SECRET not set. Set them in .env for production security."
  );
}

const JWT_EXPIRES = process.env.JWT_EXPIRES || "7d"; // access token lifetime
const REFRESH_TOKEN_EXPIRES = process.env.REFRESH_TOKEN_EXPIRES || "30d"; // refresh token lifetime

// ===== Rate Limiting (tuned separately for endpoints) =====
const signupLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many signup attempts, try again later" },
});

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many login attempts, try again later" },
});

const firebaseLoginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many Firebase login attempts, try again later" },
});

// ===== Helpers =====
const isValidObjectId = (id) => ObjectId.isValid(id) && String(new ObjectId(id)) === String(id);

const sanitizeString = (val) => {
  if (typeof val !== "string") return val;
  // Trim, normalize email case, strip potential script tags defensively
  let s = val.trim();
  s = s.replace(/<script[^>]*>[\s\S]*?<\/script>/gi, "");
  // Remove control chars; keep printable
  s = validator.stripLow(s, true);
  return s;
};

const validateEmail = (email) => typeof email === "string" && validator.isEmail(email);
// At least 8 characters, with upper, lower, number. Symbols allowed but not required.
const validatePassword = (password) => /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[A-Za-z\d@$!%*?&]{8,}$/.test(password || "");

const signAccessToken = (payload) =>
  jwt.sign(payload, JWT_SECRET || "dev_jwt_secret", { expiresIn: JWT_EXPIRES });

const signRefreshToken = (payload) =>
  jwt.sign(payload, REFRESH_TOKEN_SECRET || "b0a82b57e1194dde2c2bf722cca832d430cf717620f95be5a65eb29b693dbd9e977f08e64aeb0def31e4d6dc47c25868b9ff74766a7cd7d6d82fe3583b96938c", { expiresIn: REFRESH_TOKEN_EXPIRES });

// Bearer token middleware
const verifyAccessToken = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Unauthorized: No token" });
  }
  const token = authHeader.split(" ")[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET || "4adb4dadd6fcf937016a719b1ec35b9dae4d31534ec753fddb7e9c7b7c5c02cbbac37f1b2b933594d669dcfbb25757bbdef5e6bcca5af71d2335b8ae777a9e7e");
    req.user = decoded; // { id, email }
    next();
  } catch (err) {
    return res.status(401).json({
      error: err?.name === "TokenExpiredError" ? "Token expired" : "Unauthorized: Invalid token",
    });
  }
};

// Ownership check middleware (use on routes like /:id/...)
const verifyOwnership = (req, res, next) => {
  if (!req.user?.id) return res.status(401).json({ error: "Unauthorized" });
  if (String(req.params.id) !== String(req.user.id)) {
    return res.status(403).json({ error: "Forbidden: Cannot access other user's data" });
  }
  next();
};

// Utility: push refresh token to a user's token list (per-device) capped to N tokens
const pushRefreshToken = async (coll, userId, token) => {
  const MAX_TOKENS = 5; // keep last 5 sessions
  await coll.updateOne(
    { _id: new ObjectId(userId) },
    {
      $push: { refreshTokens: { $each: [token], $slice: -MAX_TOKENS } },
      $set: { updatedAt: new Date() },
    }
  );
};

// ===== REGISTER CUSTOMER =====
router.post("/", signupLimiter, async (req, res) => {
  try {
    let { fullName, email, password, phone, firebaseUid, photo } = req.body || {};

    fullName = sanitizeString(fullName) || "User";
    email = sanitizeString(email)?.toLowerCase();
    phone = sanitizeString(phone) || "";
    photo = sanitizeString(photo) || "";
    firebaseUid = sanitizeString(firebaseUid) || "";

    if (!email || !validateEmail(email)) {
      return res.status(400).json({ error: "Valid email is required" });
    }

    if (!password && !firebaseUid) {
      return res.status(400).json({ error: "Password is required for email signup" });
    }

    if (password && !validatePassword(password)) {
      return res.status(400).json({
        error: "Password must be at least 8 chars with upper, lower, and a number",
      });
    }

    const coll = getCustomersCollection();

    // unique by email
    const existing = await coll.findOne({ email });
    if (existing) {
      return res.status(409).json({ error: "Email already registered" });
    }

    const hashedPassword = password ? await bcrypt.hash(password, 12) : null;
    const loginMethod = password ? "email" : "google"; // or "firebase"

    const newCustomer = {
      fullName,
      email,
      password: hashedPassword,
      phone,
      firebaseUid,
      photo,
      isActive: true,
      loginMethod,
      loginAttempts: 0,
      refreshTokens: [], // keep multiple devices
      createdAt: new Date(),
      updatedAt: new Date(),
      lastLogin: null,
    };

    const result = await coll.insertOne(newCustomer);
    const id = result.insertedId.toString();

    const accessToken = signAccessToken({ id, email });
    const refreshToken = signRefreshToken({ id });

    await pushRefreshToken(coll, id, refreshToken);

    return res.status(201).json({
      message: "Customer created successfully",
      accessToken,
      refreshToken,
      customer: {
        id,
        fullName,
        email,
        phone,
        photo,
        loginMethod,
      },
    });
  } catch (err) {
    console.error("[REGISTER]", err);
    return res.status(500).json({ error: "Registration failed" });
  }
});

// ===== LOGIN CUSTOMER (email + password) =====
router.post("/login", loginLimiter, async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) {
      return res.status(400).json({ error: "Email and password are required" });
    }

    const coll = getCustomersCollection();
    const customer = await coll.findOne({ email: String(email).toLowerCase() });

    if (!customer) return res.status(401).json({ error: "Invalid credentials" });

    if (!customer.password) {
      return res.status(400).json({ error: "This account uses Google/Firebase login" });
    }

    const match = await bcrypt.compare(password, customer.password);
    if (!match) return res.status(401).json({ error: "Invalid credentials" });

    const id = customer._id.toString();
    const accessToken = signAccessToken({ id, email: customer.email });
    const refreshToken = signRefreshToken({ id });

    await pushRefreshToken(coll, id, refreshToken);
    await coll.updateOne(
      { _id: customer._id },
      { $set: { lastLogin: new Date(), updatedAt: new Date() } }
    );

    const { password: _pw, refreshTokens: _rt, ...safeCustomer } = customer;

    return res.json({ accessToken, refreshToken, customer: { ...safeCustomer, id } });
  } catch (err) {
    console.error("[LOGIN]", err);
    return res.status(500).json({ error: "Login failed" });
  }
});

// ===== FIREBASE / GOOGLE LOGIN =====
router.post("/firebase-login", firebaseLoginLimiter, verifyFirebaseToken, async (req, res) => {
  try {
    const { uid, email, name, picture, phone_number } = req.user || {};

    if (!email || !validator.isEmail(String(email))) {
      return res.status(400).json({ error: "Firebase user must provide a valid email" });
    }

    const coll = getCustomersCollection();
    let customer = await coll.findOne({ email: String(email).toLowerCase() });

    if (!customer) {
      const doc = {
        firebaseUid: uid || "",
        fullName: sanitizeString(name) || "Firebase User",
        email: String(email).toLowerCase(),
        photo: sanitizeString(picture) || "",
        phone: sanitizeString(phone_number) || "",
        isActive: true,
        loginMethod: "google",
        loginAttempts: 0,
        refreshTokens: [],
        createdAt: new Date(),
        updatedAt: new Date(),
        lastLogin: new Date(),
      };
      const result = await coll.insertOne(doc);
      customer = { _id: result.insertedId, ...doc };
    } else {
      const update = { lastLogin: new Date(), updatedAt: new Date() };
      if (!customer.firebaseUid && uid) update.firebaseUid = uid;
      await coll.updateOne({ _id: customer._id }, { $set: update });
    }

    const id = customer._id.toString();
    const accessToken = signAccessToken({ id, email: customer.email });
    const refreshToken = signRefreshToken({ id });

    await pushRefreshToken(coll, id, refreshToken);

    return res.json({
      accessToken,
      refreshToken,
      customer: {
        id,
        fullName: customer.fullName,
        email: customer.email,
        photo: customer.photo || "",
        phone: customer.phone || "",
        loginMethod: "google",
      },
    });
  } catch (err) {
    console.error("[FIREBASE LOGIN]", err);
    return res.status(500).json({ error: "Firebase login failed" });
  }
});

// ===== TOKEN REFRESH (ROTATION) =====
router.post("/token/refresh", async (req, res) => {
  try {
    const { refreshToken } = req.body || {};
    if (!refreshToken) return res.status(400).json({ error: "refreshToken is required" });

    let payload;
    try {
      payload = jwt.verify(refreshToken, REFRESH_TOKEN_SECRET || "b0a82b57e1194dde2c2bf722cca832d430cf717620f95be5a65eb29b693dbd9e977f08e64aeb0def31e4d6dc47c25868b9ff74766a7cd7d6d82fe3583b96938c");
    } catch (err) {
      return res.status(401).json({ error: "Invalid or expired refresh token" });
    }

    const userId = payload.id;
    if (!isValidObjectId(userId)) return res.status(400).json({ error: "Invalid user id in token" });

    const coll = getCustomersCollection();
    const user = await coll.findOne({ _id: new ObjectId(userId) });
    if (!user || !Array.isArray(user.refreshTokens)) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    // Token rotation: only allow if the token exists in DB; then rotate (remove old, add new)
    const hasToken = user.refreshTokens.includes(refreshToken);
    if (!hasToken) return res.status(401).json({ error: "Refresh token not recognized" });

    const newAccess = signAccessToken({ id: userId, email: user.email });
    const newRefresh = signRefreshToken({ id: userId });

    await coll.updateOne(
      { _id: new ObjectId(userId) },
      {
        $pull: { refreshTokens: refreshToken },
        $push: { refreshTokens: { $each: [newRefresh], $slice: -5 } },
        $set: { updatedAt: new Date() },
      }
    );

    return res.json({ accessToken: newAccess, refreshToken: newRefresh });
  } catch (err) {
    console.error("[TOKEN REFRESH]", err);
    return res.status(500).json({ error: "Token refresh failed" });
  }
});

// ===== LOGOUT (revoke a single refresh token) =====
router.post("/logout", async (req, res) => {
  try {
    const { refreshToken } = req.body || {};
    if (!refreshToken) return res.status(400).json({ error: "refreshToken is required" });

    let payload;
    try {
      payload = jwt.verify(refreshToken, REFRESH_TOKEN_SECRET || "b0a82b57e1194dde2c2bf722cca832d430cf717620f95be5a65eb29b693dbd9e977f08e64aeb0def31e4d6dc47c25868b9ff74766a7cd7d6d82fe3583b96938c");
    } catch (err) {
      // Even if invalid/expired, respond OK to avoid token probing
      return res.json({ message: "Logged out" });
    }

    const userId = payload.id;
    if (!isValidObjectId(userId)) return res.json({ message: "Logged out" });

    const coll = getCustomersCollection();
    await coll.updateOne(
      { _id: new ObjectId(userId) },
      { $pull: { refreshTokens: refreshToken }, $set: { updatedAt: new Date() } }
    );

    return res.json({ message: "Logged out" });
  } catch (err) {
    console.error("[LOGOUT]", err);
    return res.status(500).json({ error: "Logout failed" });
  }
});

// ===== Example protected route =====
router.get("/me", verifyAccessToken, async (req, res) => {
  try {
    const coll = getCustomersCollection();
    const user = await coll.findOne({ _id: new ObjectId(req.user.id) });
    if (!user) return res.status(404).json({ error: "User not found" });

    const { password, refreshTokens, ...safe } = user;
    return res.json({ ...safe, id: user._id.toString() });
  } catch (err) {
    console.error("[ME]", err);
    return res.status(500).json({ error: "Failed to fetch profile" });
  }
});

module.exports = router;
