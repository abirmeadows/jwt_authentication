const express = require('express')
const router = express()
const {
  verifyUser,
  register,
  login,
  refreshToken,
  logout,
} = require('../controllers/auth')
const { verifyAccessToken } = require('../helpers/jwt_helper')

router.post('/verifyuser', verifyAccessToken, verifyUser)
router.post('/register', register)
router.post('/login', login)
router.post('/refreshtoken', refreshToken)
router.delete('/logout', logout)

module.exports = router
