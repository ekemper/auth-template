const mongoose = require('mongoose')

mongoose
  .connect(process.env.DB_CONNECTION_URI)
  .then(() => {})
  .catch(err => {
    console.error('Database connection error', { err })
  })

const db = mongoose.connection
db.on('error', console.error.bind(console, 'connection error:'))
db.once('open', () => {
  //console.log('mongo connection established')
  let schema = new mongoose.Schema({
    description: String
  })
  const Listing = db.model('Listing', schema)
  const testListing = new Listing({ description: 'Silence' })
  testListing.save(function(err, fluffy) {
    if (err) return console.error(err)
    console.log('saved', { testListing })
  })
})

module.exports = db
