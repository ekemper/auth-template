let ListingModel = require('../models/Listing.js')

const delegateAction = action => {
  console.log('RXd ', { action })

  ListingModel.find({
    description: 'Silence'
  })
    .then(doc => {
      console.log({ doc })
    })
    .catch(err => {
      console.error({ err })
    })
}

module.exports = {
  delegateAction
}
