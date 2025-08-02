// routes/email.js
const express = require('express');
const nodemailer = require('nodemailer');
const router = express.Router();
require('dotenv').config();

router.post('/send-email', async (req, res) => {
  const { from_name, from_email, message } = req.body;

  try {
    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.MAIL_USER,        // e.g. your Gmail
        pass: process.env.MAIL_PASS         // App password
      }
    });

    const mailOptions = {
      from: from_email,
      to: 'jhadam904@gmail.com',
      subject: `Message from ${from_name}`,
      text: message
    };

    await transporter.sendMail(mailOptions);
    res.status(200).json({ message: 'Email sent successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to send email' });
  }
});

module.exports = router;
