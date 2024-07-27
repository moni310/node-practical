const express = require('express');
const userCtrl = require('../controllers/users')
const router = express.Router();

router.post('/register', userCtrl.register);
router.post('/verify', userCtrl.verifyEmail);
router.post('/admin/login', userCtrl.adminLogin);
router.post('/login', userCtrl.login);


module.exports = router;
