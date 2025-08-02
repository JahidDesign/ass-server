const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const { connectDB } = require('./db');

const hotelRoutes = require('./routes/hotels');
const tourRoutes = require('./routes/tours');
const flightRoutes = require('./routes/flights');
const teamsMemberRoutes = require('./routes/teamsMember');

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

app.use('/hotels', hotelRoutes);
app.use('/tours', tourRoutes);
app.use('/flights', flightRoutes);
app.use('/teams', teamsMemberRoutes);

app.delete('/admin/delete', (req, res) => {
  const adminEmail = req.headers['jhadam904@gmail.com'];

  if (adminEmail !== process.env.ADMIN_EMAIL) {
    return res.status(403).json({ error: 'Access denied: Admin only' });
  }

  res.json({ message: 'Admin deletion access granted' });
});

app.get('/', (req, res) => {
  res.send('Travel API is running...');
});

app.use((req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

app.use((err, req, res, next) => {
  console.error('Server Error:', err);
  res.status(500).json({ error: 'Internal Server Error' });
});

connectDB()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`Server running at http://localhost:${PORT}`);
    });
  })
  .catch((err) => {
    console.error('Failed to connect to the database:', err);
  });
