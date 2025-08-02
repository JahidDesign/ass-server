const express = require('express');
const { ObjectId } = require('mongodb');
const { getTeamsMembertCollection } = require('../db');

const router = express.Router();

// ========== GET All Team Members ==========
router.get('/', async (req, res) => {
  try {
    const members = await getTeamsMembertCollection().find().toArray();
    res.status(200).json(members);
  } catch (error) {
    console.error('[GET /teams] Error:', error);
    res.status(500).json({ error: 'Failed to fetch team members' });
  }
});

// ========== GET Team Member by ID ==========
router.get('/:id', async (req, res) => {
  const { id } = req.params;

  if (!ObjectId.isValid(id)) {
    return res.status(400).json({ error: 'Invalid ID format' });
  }

  try {
    const member = await getTeamsMembertCollection().findOne({ _id: new ObjectId(id) });
    if (!member) {
      return res.status(404).json({ error: 'Team member not found' });
    }
    res.status(200).json(member);
  } catch (error) {
    console.error(`[GET /teams/${id}] Error:`, error);
    res.status(500).json({ error: 'Failed to retrieve team member' });
  }
});

// ========== POST Create New Team Member ==========
router.post('/', async (req, res) => {
  const member = req.body;

  // Updated required fields (no longer using 'role')
  const requiredFields = ['name', 'title', 'description', 'photoUrl', 'position'];
  const missingFields = requiredFields.filter((field) => !member[field]);

  if (missingFields.length > 0) {
    return res.status(400).json({ error: `Missing fields: ${missingFields.join(', ')}` });
  }

  try {
    const result = await getTeamsMembertCollection().insertOne(member);
    res.status(201).json({
      message: 'Team member created successfully',
      insertedId: result.insertedId,
    });
  } catch (error) {
    console.error('[POST /teams] Error:', error);
    res.status(500).json({ error: 'Failed to create team member' });
  }
});

// ========== PUT Update Team Member by ID ==========
router.put('/:id', async (req, res) => {
  const { id } = req.params;
  const updateData = req.body;

  if (!ObjectId.isValid(id)) {
    return res.status(400).json({ error: 'Invalid ID format' });
  }

  try {
    const result = await getTeamsMembertCollection().updateOne(
      { _id: new ObjectId(id) },
      { $set: updateData }
    );

    if (result.matchedCount === 0) {
      return res.status(404).json({ error: 'Team member not found' });
    }

    res.status(200).json({ message: 'Team member updated successfully' });
  } catch (error) {
    console.error(`[PUT /teams/${id}] Error:`, error);
    res.status(500).json({ error: 'Failed to update team member' });
  }
});

// ========== DELETE Team Member by ID ==========
router.delete('/:id', async (req, res) => {
  const { id } = req.params;

  if (!ObjectId.isValid(id)) {
    return res.status(400).json({ error: 'Invalid ID format' });
  }

  try {
    const result = await getTeamsMembertCollection().deleteOne({ _id: new ObjectId(id) });

    if (result.deletedCount === 0) {
      return res.status(404).json({ error: 'Team member not found' });
    }

    res.status(200).json({ message: 'Team member deleted successfully' });
  } catch (error) {
    console.error(`[DELETE /teams/${id}] Error:`, error);
    res.status(500).json({ error: 'Failed to delete team member' });
  }
});

module.exports = router;
