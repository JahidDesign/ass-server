const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');

const uri = `mongodb+srv://${process.env.USER_NAME}:${process.env.USER_PASS}@cluster0.obhimbe.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

async function connectDB(app) {
  try {
    await client.connect();
    console.log('✅ MongoDB connected');

    const db = client.db('hotelDB');
    const hotelsCollection = db.collection('hotels');
    const toursCollection = db.collection('tours');
    const airTicktCollection = db.collection('airTickt');
    // === Hotel Routes ===
    app.get('/hotels', async (req, res) => {
      try {
        const hotels = await hotelsCollection.find().toArray();
        res.json(hotels);
      } catch (err) {
        res.status(500).json({ error: 'Failed to fetch hotels' });
      }
    });

    app.get('/hotels/:id', async (req, res) => {
      try {
        const hotel = await hotelsCollection.findOne({ _id: new ObjectId(req.params.id) });
        hotel
          ? res.json(hotel)
          : res.status(404).json({ error: 'Hotel not found' });
      } catch (err) {
        res.status(400).json({ error: 'Invalid hotel ID' });
      }
    });

    app.post('/hotels', async (req, res) => {
      try {
        const result = await hotelsCollection.insertOne(req.body);
        res.status(201).json({ message: 'Hotel added', insertedId: result.insertedId });
      } catch (err) {
        res.status(400).json({ error: 'Failed to add hotel' });
      }
    });

    app.put('/hotels/:id', async (req, res) => {
      try {
        const result = await hotelsCollection.updateOne(
          { _id: new ObjectId(req.params.id) },
          { $set: req.body },
          { upsert: true }
        );
        res.json({ message: 'Hotel updated', result });
      } catch (err) {
        res.status(400).json({ error: 'Failed to update hotel' });
      }
    });

    app.delete('/hotels/:id', async (req, res) => {
      try {
        const result = await hotelsCollection.deleteOne({ _id: new ObjectId(req.params.id) });
        result.deletedCount
          ? res.json({ message: 'Hotel deleted successfully' })
          : res.status(404).json({ error: 'Hotel not found' });
      } catch (err) {
        res.status(400).json({ error: 'Failed to delete hotel' });
      }
    });

    // === Tour Booking Routes ===
    app.get('/tours', async (req, res) => {
      try {
        const bookings = await toursCollection.find().toArray();
        res.json(bookings);
      } catch (err) {
        res.status(500).json({ error: 'Failed to fetch tour bookings' });
      }
    });

    app.get('/tours/:id', async (req, res) => {
      try {
        const booking = await toursCollection.findOne({ _id: new ObjectId(req.params.id) });
        booking
          ? res.json(booking)
          : res.status(404).json({ error: 'Booking not found' });
      } catch (err) {
        res.status(400).json({ error: 'Invalid booking ID' });
      }
    });

    app.post('/tours', async (req, res) => {
      try {
        const result = await toursCollection.insertOne(req.body);
        res.status(201).json({ message: 'Booking created', insertedId: result.insertedId });
      } catch (err) {
        res.status(400).json({ error: 'Failed to create booking' });
      }
    });

    app.put('/tours/:id', async (req, res) => {
      try {
        const result = await toursCollection.updateOne(
          { _id: new ObjectId(req.params.id) },
          { $set: req.body },
          { upsert: true }
        );
        res.json({ message: 'Booking updated', result });
      } catch (err) {
        res.status(400).json({ error: 'Failed to update booking' });
      }
    });

    app.delete('/tours/:id', async (req, res) => {
      try {
        const result = await toursCollection.deleteOne({ _id: new ObjectId(req.params.id) });
        result.deletedCount
          ? res.json({ message: 'Booking deleted successfully' })
          : res.status(404).json({ error: 'Booking not found' });
      } catch (err) {
        res.status(400).json({ error: 'Failed to delete booking' });
      }
    });
  // === airTickt Booking Routes ===
    app.get('/airTickt', async (req, res) => {
      try {
        const bookings = await airTicktCollection.find().toArray();
        res.json(bookings);
      } catch (err) {
        res.status(500).json({ error: 'Failed to fetch tour bookings' });
      }
    });

    app.get('/airTickt/:id', async (req, res) => {
      try {
        const booking = await airTicktCollection.findOne({ _id: new ObjectId(req.params.id) });
        booking
          ? res.json(booking)
          : res.status(404).json({ error: 'Booking not found' });
      } catch (err) {
        res.status(400).json({ error: 'Invalid booking ID' });
      }
    });

    app.post('/airTickt', async (req, res) => {
      try {
        const result = await airTicktCollection.insertOne(req.body);
        res.status(201).json({ message: 'Booking created', insertedId: result.insertedId });
      } catch (err) {
        res.status(400).json({ error: 'Failed to create booking' });
      }
    });

    app.put('/airTickt/:id', async (req, res) => {
      try {
        const result = await airTicktCollection.updateOne(
          { _id: new ObjectId(req.params.id) },
          { $set: req.body },
          { upsert: true }
        );
        res.json({ message: 'Booking updated', result });
      } catch (err) {
        res.status(400).json({ error: 'Failed to update booking' });
      }
    });

    app.delete('/airTickt/:id', async (req, res) => {
      try {
        const result = await airTicktCollection.deleteOne({ _id: new ObjectId(req.params.id) });
        result.deletedCount
          ? res.json({ message: 'Booking deleted successfully' })
          : res.status(404).json({ error: 'Booking not found' });
      } catch (err) {
        res.status(400).json({ error: 'Failed to delete booking' });
      }
    });
  } catch (err) {
    console.error('❌ MongoDB connection error:', err);
  }
}

module.exports = connectDB;
