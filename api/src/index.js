//const bodyParser = require('body-parser')
require('dotenv').config()

const { PORT } = require('../config/env.config')
const { router } = require('./server/router/index.router')
const { requestLogger, log } = require('./util/logger')
var app = require('express')()
var cors = require('cors')
var http = require('http').Server(app)
//var socket = require('socket.io')(http)
//const { delegateAction } = require('./server/handlers/delegation')
app.use(cors())
const db = require('./util/mongooseClient')

http.listen(PORT, () => {
  console.log(`listening on ${PORT}`)
})

app.use(requestLogger)

//app.use(bodyParser.json())
//app.use(bodyParser.urlencoded({ extended: false }))

// app.use((req, res, next) => {
//   res.header('Access-Control-Allow-Origin', 'http://localhost:8080')
//   res.header('Access-Control-Allow-Credentials', 'true')
//   res.header(
//     'Access-Control-Allow-Headers',
//     'Origin, X-Requested-With, Content-Type, Accept'
//   )
//   next()
// })

app.use('/', router)

// socket.on('connection', socketInstance => {
//   console.log('connected client ', socketInstance.id)

//   socketInstance.on('action', delegateAction)

//   socketInstance.on('disconnect', () => {
//     console.log('disconnected client ', socketInstance.id)
//   })
// })
