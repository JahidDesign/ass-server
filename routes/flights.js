const express = require('express');
const { ObjectId } = require('mongodb');
const { getAirTicktCollection } = require('../db');

const router = express.Router();

// ========= GET All Flight Bookings =========
router.get('/', async (req, res) => {
  try {
    const bookings = await getAirTicktCollection().find().toArray();
    res.status(200).json(bookings);
  } catch (error) {
    console.error('❌ [GET /flights] Failed to fetch bookings:', error);
    res.status(500).json({ error: 'Failed to fetch bookings' });
  }
});

// ========= GET Booking by ID =========
router.get('/:id', async (req, res) => {
  const { id } = req.params;

  if (!ObjectId.isValid(id)) {
    return res.status(400).json({ error: 'Invalid booking ID' });
  }

  try {
    const booking = await getAirTicktCollection().findOne({ _id: new ObjectId(id) });

    if (!booking) {
      return res.status(404).json({ error: 'Booking not found' });
    }

    res.status(200).json(booking);
  } catch (error) {
    console.error(`❌ [GET /flights/${id}] Error:`, error);
    res.status(500).json({ error: 'Failed to retrieve booking' });
  }
});

// ========= CREATE New Booking =========
router.post('/', async (req, res) => {
  const booking = req.body;
  const requiredFields = ['passengerName', 'email', 'departure', 'arrival'];

  const missing = requiredFields.filter(field => !booking[field]);
  if (missing.length > 0) {
    return res.status(400).json({ error: `Missing fields: ${missing.join(', ')}` });
  }

  try {
    const result = await getAirTicktCollection().insertOne(booking);
    res.status(201).json({
      message: 'Booking created successfully',
      insertedId: result.insertedId,
    });
  } catch (error) {
    console.error('❌ [POST /flights] Failed to create booking:', error);
    res.status(500).json({ error: 'Failed to create booking' });
  }
});

// ========= UPDATE Booking by ID =========
router.put('/:id', async (req, res) => {
  const { id } = req.params;
  const updatedBooking = req.body;

  if (!ObjectId.isValid(id)) {
    return res.status(400).json({ error: 'Invalid booking ID' });
  }

  try {
    const result = await getAirTicktCollection().updateOne(
      { _id: new ObjectId(id) },
      { $set: updatedBooking }
    );

    if (result.matchedCount === 0) {
      return res.status(404).json({ error: 'Booking not found' });
    }

    res.status(200).json({ message: 'Booking updated successfully' });
  } catch (error) {
    console.error(`❌ [PUT /flights/${id}] Error:`, error);
    res.status(500).json({ error: 'Failed to update booking' });
  }
});

// ========= DELETE Booking by ID =========
router.delete('/:id', async (req, res) => {
  const { id } = req.params;

  if (!ObjectId.isValid(id)) {
    return res.status(400).json({ error: 'Invalid booking ID' });
  }

  try {
    const result = await getAirTicktCollection().deleteOne({ _id: new ObjectId(id) });

    if (result.deletedCount === 0) {
      return res.status(404).json({ error: 'Booking not found' });
    }

    res.status(200).json({ message: 'Booking deleted successfully' });
  } catch (error) {
    console.error(`❌ [DELETE /flights/${id}] Error:`, error);
    res.status(500).json({ error: 'Failed to delete booking' });
  }
});

module.exports = router;
