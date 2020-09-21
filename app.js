const express = require('express')
const morgan = require('morgan')
const createError = require('http-errors')
const dotenv = require('dotenv')
require('./helpers/init_mongodb')
require('./helpers/init_redis')

dotenv.config()

const app = express()

app.use(morgan('dev'))

app.use(express.json())
app.use(express.urlencoded({ extended: true }))

app.get('/', async (req, res, next) => {
  res.send('Express server')
})

app.use('/auth', require('./routes/auth'))

app.use(async (req, res, next) => {
  next(createError.NotFound())
})

app.use((err, req, res, next) => {
  res.status(err.status || 500)
  res.send({
    error: {
      status: err.status || 500,
      message: err.message,
    },
  })
})

const PORT = process.env.PORT || 5000

app.listen(PORT, () => console.log('Express server running'))
