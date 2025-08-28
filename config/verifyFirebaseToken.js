// middleware/verifyFirebaseToken.js
const admin = require("firebase-admin");
require("dotenv").config();

const keyPath = process.env.FIREBASE_KEY || "./service.json";

try {
  // initialize if not already initialized
  if (!admin.apps.length) {
    const serviceAccount = require(keyPath);
    admin.initializeApp({
      credential: admin.credential.cert(serviceAccount),
    });
    console.log("Firebase admin initialized");
  }
} catch (err) {
  console.error("Failed to load Firebase service account key:", err.message);
  // don't exit here; let initialization fail loudly when used
}

async function verifyFirebaseToken(req, res, next) {
  const header = req.headers["authorization"];
  if (!header || !header.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Missing Firebase ID token" });
  }
  const idToken = header.split(" ")[1];
  try {
    const decoded = await admin.auth().verifyIdToken(idToken);
    // decoded contains: uid, email, name (maybe), picture (maybe), phone_number (maybe)
    req.firebaseUser = {
      uid: decoded.uid,
      email: decoded.email,
      name: decoded.name || decoded.name || decoded.displayName,
      picture: decoded.picture || decoded.photoURL,
      phone_number: decoded.phone_number || decoded.phoneNumber,
    };
    next();
  } catch (err) {
    console.error("verifyFirebaseToken error:", err.message);
    return res.status(401).json({ error: "Invalid/expired Firebase token" });
  }
}

module.exports = verifyFirebaseToken;
