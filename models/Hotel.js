const mongoose = require("mongoose");

const hotelSchema = new mongoose.Schema({
  hotelName: String,
  hotelPrice: Number,
  hotelLocation: String,
  features: {
    wifi: Boolean,
    restaurant: Boolean,
    parking: Boolean,
    conference: Boolean,
    banquet: Boolean,
  },
  googleMap: String,
  starRating: Number,
  description: String,
  photoUrl: String,
});

module.exports = mongoose.model("hotels", hotelSchema);
