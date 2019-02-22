let mongoose = require('mongoose')
let schema = new mongoose.Schema({
  email: String,
  firstName: String,
  fullName: String,
  lastName: String,
  profileImage: String,
  isAdmin: Boolean
})
module.exports = mongoose.model('user', schema)
