var faker = require('faker');

const db = require('./util/mongooseClient')

const User = db.model('User', schema)

const testListing = new User({
    email: faker.internet.email(),
    firstName: faker.name.firstName(),
    lastName: faker.name.lastName(),
    profileImage: String
})

testListing.save(function (err, fluffy) {
    if (err) return console.error(err)
    console.log('saved', { testListing })
})