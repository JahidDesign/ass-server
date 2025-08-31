// middleware/auth.js
const admin = require("firebase-admin");
const jwt = require('jsonwebtoken');
const serviceAccount = require("../server.json");

// Initialize Firebase Admin if not already
if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
  });
}

// Firebase token verification middleware
const verifyFirebaseToken = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ error: "Unauthorized: No token" });
    }

    const idToken = authHeader.split(" ")[1];
    const decodedToken = await admin.auth().verifyIdToken(idToken);

    req.user = {
      uid: decodedToken.uid,
      email: decodedToken.email,
      name: decodedToken.name,
      picture: decodedToken.picture,
      phone_number: decodedToken.phone_number,
    };

    next();
  } catch (err) {
    console.error("Firebase token verification failed:", err);
    res.status(401).json({ error: "Unauthorized: Invalid Firebase token" });
  }
};

// JWT verification middleware
const verifyJWT = (req, res, next) => {
  const token = req.header('Authorization')?.replace('Bearer ', '');
  if (!token) return res.status(401).send({ error: 'Access denied. No token provided.' });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(400).send({ error: 'Invalid token.' });
  }
};

// Export both middlewares
module.exports = {
  verifyFirebaseToken,
  verifyJWT,
};
