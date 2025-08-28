const { MongoClient, ServerApiVersion } = require('mongodb');
require('dotenv').config();

// MongoDB URI
const uri = `mongodb+srv://${process.env.USER_NAME}:${process.env.USER_PASS}@cluster0.obhimbe.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;

// MongoDB client setup
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

// Collection references
let db;
let hotelsCollection;
let toursCollection;
let airTicktCollection;
let teamsMemberCollection;
let visitorsCollection;
let bookingsCollection;
let hotelBookingsCollection;
let CustomerCollection;

// Connect to MongoDB and initialize collections
async function connectDB() {
  try {
    await client.connect();
    db = client.db('hotelDB');

    hotelsCollection = db.collection('hotels');
    toursCollection = db.collection('tours');
    airTicktCollection = db.collection('flights');
    teamsMemberCollection = db.collection('teams');
    visitorsCollection = db.collection('visitors');
    bookingsCollection = db.collection('bookings');
    hotelBookingsCollection = db.collection('hotelbook');
    CustomerCollection = db.collection('customers');

    console.log('✅ MongoDB connected successfully');
  } catch (error) {
    console.error('❌ Failed to connect to MongoDB:', error);
    process.exit(1); // Exit the server if DB connection fails
  }
}

// Export collection accessors with safety checks
function getHotelsCollection() {
  if (!hotelsCollection) throw new Error('❌ Hotels collection not initialized. Call connectDB first.');
  return hotelsCollection;
}

function getToursCollection() {
  if (!toursCollection) throw new Error('❌ Tours collection not initialized. Call connectDB first.');
  return toursCollection;
}

function getAirTicktCollection() {
  if (!airTicktCollection) throw new Error('❌ Flights collection not initialized. Call connectDB first.');
  return airTicktCollection;
}

function getTeamsMembertCollection() {
  if (!teamsMemberCollection) throw new Error('❌ TeamsMember collection not initialized. Call connectDB first.');
  return teamsMemberCollection;
}
function getvisitorsCollection() {
  if (!visitorsCollection) throw new Error('❌ TeamsMember collection not initialized. Call connectDB first.');
  return visitorsCollection;
}
function getbookingsCollection() {
  if (!bookingsCollection) throw new Error('❌ TeamsMember collection not initialized. Call connectDB first.');
  return bookingsCollection;
}
function gethotelBookingsCollection() {
  if (!hotelBookingsCollection) throw new Error('❌ TeamsMember collection not initialized. Call connectDB first.');
  return hotelBookingsCollection;
}
function getCustomerCollection() {
  if (!CustomerCollection) throw new Error('❌ TeamsMember collection not initialized. Call connectDB first.');
  return CustomerCollection;
}

// Export functions
module.exports = {
  connectDB,
  getHotelsCollection,
  getToursCollection,
  getAirTicktCollection,
  getTeamsMembertCollection,
  getvisitorsCollection,
  getbookingsCollection,
  gethotelBookingsCollection,
  getCustomerCollection,
};
