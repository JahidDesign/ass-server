// routes/tours.js
const express = require('express');
const { ObjectId } = require('mongodb');
const { gethotelBookingsCollection } = require('../db');

const router = express.Router();

router.get('/', async (req, res) => {
  try {
    const bookings = await gethotelBookingsCollection().find().toArray();
    res.json(bookings);
  } catch {
    res.status(500).json({ error: 'Failed to fetch tour bookings' });
  }
});

router.get('/:id', async (req, res) => {
  try {
    const booking = await gethotelBookingsCollection().findOne({ _id: new ObjectId(req.params.id) });
    booking ? res.json(booking) : res.status(404).json({ error: 'Booking not found' });
  } catch {
    res.status(400).json({ error: 'Invalid booking ID' });
  }
});

router.post('/', async (req, res) => {
  try {
    const result = await gethotelBookingsCollection().insertOne(req.body);
    res.status(201).json({ message: 'Booking created', insertedId: result.insertedId });
  } catch {
    res.status(400).json({ error: 'Failed to create booking' });
  }
});

router.put('/:id', async (req, res) => {
  try {
    const result = await gethotelBookingsCollection().updateOne(
      { _id: new ObjectId(req.params.id) },
      { $set: req.body },
      { upsert: true }
    );
    res.json({ message: 'Booking updated', result });
  } catch {
    res.status(400).json({ error: 'Failed to update booking' });
  }
});

router.delete('/:id', async (req, res) => {
  try {
    const result = await gethotelBookingsCollection().deleteOne({ _id: new ObjectId(req.params.id) });
    result.deletedCount
      ? res.json({ message: 'Booking deleted successfully' })
      : res.status(404).json({ error: 'Booking not found' });
  } catch {
    res.status(400).json({ error: 'Failed to delete booking' });
  }
});

module.exports = router;
