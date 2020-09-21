const express = require('express')
const router = express()
const { register, login, refreshToken, logout } = require('../controllers/auth')

router.post('/register', register)
router.post('/login', login)
router.post('/refreshtoken', refreshToken)
router.delete('/logout', logout)

module.exports = router
