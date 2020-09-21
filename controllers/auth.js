const createError = require('http-errors')
const User = require('../models/User')
const { authSchema } = require('../helpers/validation_schema')
const {
  signAccessToken,
  signRefreshToken,
  verifyRefreshToken,
} = require('../helpers/jwt_helper')
const client = require('../helpers/init_redis')

module.exports = {
  register: async (req, res, next) => {
    try {
      const result = await authSchema.validateAsync(req.body)

      const userExist = await User.findOne({ email: result.email })

      if (userExist)
        throw createError.Conflict(`${result.email} is already registered`)

      const user = new User({
        email: result.email,
        password: result.password,
      })

      const savedUser = await user.save()

      const accessToken = await signAccessToken(savedUser.id)
      const refreshToken = await signRefreshToken(savedUser.id)

      res.send({ accessToken, refreshToken })
    } catch (err) {
      if (err.isJoi === true) err.status = 422
      next(err)
    }
  },
  login: async (req, res, next) => {
    try {
      const result = await authSchema.validateAsync(req.body)

      const user = await User.findOne({ email: result.email })

      if (!user) throw createError.NotFound('User not registered')

      const isMatch = await user.isValidPassword(result.password)

      if (!isMatch) throw createError.Unauthorized('Email/Password not valid')

      const accessToken = await signAccessToken(user.id)
      const refreshToken = await signRefreshToken(user.id)

      res.send({ accessToken, refreshToken })
    } catch (err) {
      if (err.isJoi === true)
        return next(createError.BadRequest('Invalid Email/Password'))
      next(err)
    }
  },
  refreshToken: async (req, res, next) => {
    try {
      const { refreshToken } = req.body

      if (!refreshToken) throw createError.BadRequest()

      const userId = await verifyRefreshToken(refreshToken)

      const accessToken = await signAccessToken(userId)
      const refToken = await signRefreshToken(userId)

      res.send({ accessToken: accessToken, refreshToken: refToken })
    } catch (err) {
      next(err)
    }
  },
  logout: async (req, res, next) => {
    try {
      const { refreshToken } = req.body

      if (!refreshToken) throw createError.BadRequest()

      const userId = await verifyRefreshToken(refreshToken)

      client.DEL(userId, (err, value) => {
        if (err) {
          console.log(err.message)
          throw createError.InternalServerError()
        }

        console.log(value)
        res.sendStatus(204)
      })
    } catch (err) {
      next(err)
    }
  },
}
