// routes/hotels.js
const express = require('express');
const { ObjectId } = require('mongodb');
const { getHotelsCollection } = require('../db');

const router = express.Router();

router.get('/', async (req, res) => {
  try {
    const hotels = await getHotelsCollection().find().toArray();
    res.json(hotels);
  } catch {
    res.status(500).json({ error: 'Failed to fetch hotels' });
  }
});

router.get('/:id', async (req, res) => {
  try {
    const hotel = await getHotelsCollection().findOne({ _id: new ObjectId(req.params.id) });
    hotel ? res.json(hotel) : res.status(404).json({ error: 'Hotel not found' });
  } catch {
    res.status(400).json({ error: 'Invalid hotel ID' });
  }
});

router.post('/', async (req, res) => {
  try {
    const result = await getHotelsCollection().insertOne(req.body);
    res.status(201).json({ message: 'Hotel added', insertedId: result.insertedId });
  } catch {
    res.status(400).json({ error: 'Failed to add hotel' });
  }
});

router.put('/:id', async (req, res) => {
  try {
    const result = await getHotelsCollection().updateOne(
      { _id: new ObjectId(req.params.id) },
      { $set: req.body },
      { upsert: true }
    );
    res.json({ message: 'Hotel updated', result });
  } catch {
    res.status(400).json({ error: 'Failed to update hotel' });
  }
});

router.delete('/:id', async (req, res) => {
  try {
    const result = await getHotelsCollection().deleteOne({ _id: new ObjectId(req.params.id) });
    result.deletedCount
      ? res.json({ message: 'Hotel deleted successfully' })
      : res.status(404).json({ error: 'Hotel not found' });
  } catch {
    res.status(400).json({ error: 'Failed to delete hotel' });
  }
});

module.exports = router;
