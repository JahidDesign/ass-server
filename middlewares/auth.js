const admin = require("firebase-admin");
const serviceAccount = require("../server.json"); // path to your Firebase service account JSON

// Initialize Firebase Admin if not already
if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
  });
}

// Middleware to verify Firebase token
const verifyFirebaseToken = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ error: "Unauthorized: No token" });
    }

    const idToken = authHeader.split(" ")[1];
    const decodedToken = await admin.auth().verifyIdToken(idToken);

    // Attach Firebase user info to request
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

module.exports = verifyFirebaseToken;
