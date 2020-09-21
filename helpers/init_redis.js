const redis = require('redis')
const dotenv = require('dotenv')

dotenv.config()

const client = redis.createClient({
  port: process.env.REDIS_PORT,
  host: process.env.REDIS_HOST,
  password: process.env.REDIS_PASSWORD,
})

client.on('connect', () => console.log('Client connected to Redis'))

client.on('ready', () =>
  console.log('Client connected to Redis and ready to use')
)

client.on('error', (err) => console.log(err.message))

client.on('end', () => console.log('Client disconnected from Redis'))

process.on('SIGINT', () => {
  client.quit()
})

module.exports = client
