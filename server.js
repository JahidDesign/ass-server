// server.js
const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const admin = require('firebase-admin');
const { connectDB } = require('./db');

// Import Routes
const hotelRoutes = require('./routes/hotels');
const tourRoutes = require('./routes/tours');
const flightRoutes = require('./routes/flights');
const teamsMemberRoutes = require('./routes/teamsMember');
const visitorsRoutes = require('./routes/visitors');
const bookingsRoutes = require('./routes/bookings');
const hotelBookingsRoutes = require('./routes/hotelbook');
const customersRouter = require("./routes/customers");

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;
const FIREBASE_KEY_PATH = process.env.FIREBASE_KEY || './server.json';
const ADMIN_EMAIL = process.env.ADMIN_EMAIL;

// === Firebase Admin Initialization ===
let serviceAccount;
try {
  serviceAccount = require(FIREBASE_KEY_PATH);
  console.log('Firebase key loaded from:', FIREBASE_KEY_PATH);
} catch (error) {
  console.error('Failed to load Firebase service account key:', error.message);
  process.exit(1);
}

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});
console.log('Firebase Admin initialized');

// === Middleware ===
app.use(cors());
app.use(express.json());

// === Firebase Token Verification Middleware ===
const verifyFirebaseToken = async (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized: Missing token' });
  }

  const idToken = authHeader.split('Bearer ')[1];

  try {
    const decodedToken = await admin.auth().verifyIdToken(idToken);
    req.user = decodedToken;
    next();
  } catch (error) {
    console.error('Token verification error:', error.code || error.message);
    res.status(401).json({ error: 'Unauthorized: Invalid or expired token' });
  }
};

// === Routes ===
app.use('/hotels', hotelRoutes);
app.use('/tours', tourRoutes);
app.use('/flights', flightRoutes);
app.use('/teams', teamsMemberRoutes);
app.use('/visitors', visitorsRoutes);
app.use('/bookings', bookingsRoutes);
app.use('/hotelbook', hotelBookingsRoutes);
app.use("/customers", customersRouter);

// === Protected Admin-Only Route Example ===
app.delete('/admin/delete', verifyFirebaseToken, (req, res) => {
  const userEmail = req.user.email;
  if (userEmail !== ADMIN_EMAIL) {
    return res.status(403).json({ error: 'Access denied: Admins only' });
  }
  res.json({ message: 'Admin deletion access granted' });
});

// === Health Check ===
app.get('/', (req, res) => {
  res.send('Travel API is running...');
});
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'ok' });
});

// === 404 Route Handler ===
app.use((req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

// === Global Error Handler ===
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'Internal Server Error' });
});

// === Start Server After DB Connection ===
connectDB()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`Server is running at http://localhost:${PORT}`);
    });
  })
  .catch((err) => {
    console.error('Failed to connect to the database:', err.message);
    process.exit(1);
  });
