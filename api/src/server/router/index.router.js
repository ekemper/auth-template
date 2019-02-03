const express = require('express')
const router = express.Router()

const googleAuthMiddleWare = require('../middleware/googleAuth')

router.get('/', function (req, res) {
  res.sendFile(__dirname + '../../../../auth-template-vue/index.html')
})

router.get('/health-check', googleAuthMiddleWare, async (req, res, next) => {

  res.json({
    message: 'healthy!',
    userID: res.userId
  })
})

module.exports = {
  router,
  basePath: '/'
}
