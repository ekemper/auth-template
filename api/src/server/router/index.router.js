const express = require('express')
const router = express.Router()

router.get('/', function (req, res) {
  res.sendFile(__dirname + '../../../../auth-template-vue/index.html')
})

router.get('/health-check', async (req, res, next) => {
  res.json({
    message: 'healthy!'
  })
})



module.exports = {
  router,
  basePath: '/'
}
