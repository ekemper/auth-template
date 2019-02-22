require('dotenv').config()
const User = require('../server/models/User');
const faker = require('faker');

const db = require('./mongooseClient')


for (let i = 0; i < 100; i++) {

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
}