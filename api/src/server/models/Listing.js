let mongoose = require('mongoose')
let schema = new mongoose.Schema({
  description: String
})
module.exports = mongoose.model('listing', schema)
