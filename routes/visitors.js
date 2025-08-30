// routes/visitors.js
const express = require('express');
const { ObjectId } = require('mongodb');
const { getvisitorsCollection } = require('../db');

const router = express.Router();

// ========================
// GET All Profiles
// ========================
router.get('/', async (req, res) => {
  try {
    const profiles = await getvisitorsCollection().find().toArray();
    res.status(200).json(profiles);
  } catch (err) {
    console.error('[GET /visitors] Error:', err);
    res.status(500).json({ error: 'Failed to fetch profiles' });
  }
});

// ========================
// GET Profile by ID
// ========================
router.get('/:id', async (req, res) => {
  const { id } = req.params;
  if (!ObjectId.isValid(id)) return res.status(400).json({ error: 'Invalid ID format' });

  try {
    const profile = await getvisitorsCollection().findOne({ _id: new ObjectId(id) });
    if (!profile) return res.status(404).json({ error: 'Profile not found' });
    res.status(200).json(profile);
  } catch (err) {
    console.error(`[GET /visitors/${id}] Error:`, err);
    res.status(500).json({ error: 'Failed to fetch profile' });
  }
});

// ========================
// POST Create or Update Profile
// ========================
router.post('/', async (req, res) => {
  const profile = req.body;

  if (!profile.email) return res.status(400).json({ error: 'Email is required' });

  try {
    const collection = getvisitorsCollection();

    // Check if profile already exists
    const existing = await collection.findOne({ email: profile.email });

    if (existing) {
      // Update existing profile
      await collection.updateOne(
        { _id: existing._id },
        { $set: profile }
      );
      const updatedProfile = await collection.findOne({ _id: existing._id });
      return res.status(200).json(updatedProfile);
    } else {
      // Create new profile
      const result = await collection.insertOne(profile);
      const newProfile = await collection.findOne({ _id: result.insertedId });
      return res.status(201).json(newProfile);
    }
  } catch (err) {
    console.error('[POST /visitors] Error:', err);
    res.status(500).json({ error: 'Failed to save profile' });
  }
});

// ========================
// PUT Update Profile by ID
// ========================
router.put('/:id', async (req, res) => {
  const { id } = req.params;
  const updateData = req.body;

  if (!ObjectId.isValid(id)) return res.status(400).json({ error: 'Invalid ID format' });

  try {
    const result = await getvisitorsCollection().updateOne(
      { _id: new ObjectId(id) },
      { $set: updateData }
    );

    if (result.matchedCount === 0) return res.status(404).json({ error: 'Profile not found' });

    const updatedProfile = await getvisitorsCollection().findOne({ _id: new ObjectId(id) });
    res.status(200).json(updatedProfile);
  } catch (err) {
    console.error(`[PUT /visitors/${id}] Error:`, err);
    res.status(500).json({ error: 'Failed to update profile' });
  }
});

// ========================
// DELETE Profile by ID
// ========================
router.delete('/:id', async (req, res) => {
  const { id } = req.params;

  if (!ObjectId.isValid(id)) return res.status(400).json({ error: 'Invalid ID format' });

  try {
    const result = await getvisitorsCollection().deleteOne({ _id: new ObjectId(id) });

    if (result.deletedCount === 0) return res.status(404).json({ error: 'Profile not found' });

    res.status(200).json({ message: 'Profile deleted successfully' });
  } catch (err) {
    console.error(`[DELETE /visitors/${id}] Error:`, err);
    res.status(500).json({ error: 'Failed to delete profile' });
  }
});

module.exports = router;
