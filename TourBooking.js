const tourBookingCollection = db.collection('tourBookings');

// === TOUR BOOKING ROUTES ===

// Create a new tour booking
app.post('/TourBooking', async (req, res) => {
  try {
    const newBooking = req.body;
    const result = await tourBookingCollection.insertOne(newBooking);
    res.status(201).json(result);
  } catch (err) {
    res.status(500).json({ error: 'Failed to create tour booking' });
  }
});

// Get all tour bookings
app.get('/TourBooking', async (req, res) => {
  try {
    const bookings = await tourBookingCollection.find().toArray();
    res.json(bookings);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch tour bookings' });
  }
});

// Get a single tour booking by ID
app.get('/TourBooking/:id', async (req, res) => {
  const { id } = req.params;
  try {
    const booking = await tourBookingCollection.findOne({ _id: new ObjectId(id) });
    booking ? res.json(booking) : res.status(404).json({ error: 'Booking not found' });
  } catch (err) {
    res.status(400).json({ error: 'Invalid ID format' });
  }
});

// Update a tour booking
app.put('/TourBooking/:id', async (req, res) => {
  const { id } = req.params;
  const updatedBooking = req.body;
  try {
    const result = await tourBookingCollection.updateOne(
      { _id: new ObjectId(id) },
      { $set: updatedBooking },
      { upsert: true }
    );
    res.json(result);
  } catch (err) {
    res.status(400).json({ error: 'Failed to update booking' });
  }
});

// Delete a tour booking
app.delete('/TourBooking/:id', async (req, res) => {
  const { id } = req.params;
  try {
    const result = await tourBookingCollection.deleteOne({ _id: new ObjectId(id) });
    result.deletedCount
      ? res.json({ message: 'Booking deleted successfully' })
      : res.status(404).json({ error: 'Booking not found' });
  } catch (err) {
    res.status(400).json({ error: 'Failed to delete booking' });
  }
});
