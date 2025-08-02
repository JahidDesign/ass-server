const admin = require('firebase-admin');
const serviceAccount = require('../firebase-server.json'); // ✅ Adjust this path if needed

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

module.exports = admin;
