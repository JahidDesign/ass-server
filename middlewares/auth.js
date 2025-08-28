// server/middleware/auth.js
const admin = require("../firebase");

async function verifyFirebaseToken(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith("Bearer ")) {
    return res.status(401).json({ message: "No token provided" });
  }

  const token = authHeader.split(" ")[1];

  try {
    const decoded = await admin.auth().verifyIdToken(token);
    req.user = decoded; // now you have uid, email, etc.
    next();
  } catch (err) {
    return res.status(403).json({ message: "Invalid token", error: err });
  }
}

module.exports = verifyFirebaseToken;
