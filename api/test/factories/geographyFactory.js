const { Factory } = require('rosie');
const faker = require('faker');

const stateFactory = new Factory().attrs({
  id: faker.address.stateAbbr(),
  name: faker.address.state(),
  countryId: faker.address.countryCode()
});

const newState = () => stateFactory.build();

const countyFactory = new Factory().attrs({
  id: faker.address.stateAbbr(),
  name: faker.address.county(),
  stateId: faker.address.stateAbbr(),
  countryId: faker.address.countryCode()
});

const newCounty = () => countyFactory.build();

module.exports = {
  newState,
  newCounty
};
