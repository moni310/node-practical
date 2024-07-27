const bcrypt = require('bcrypt')
const secretOrPrivateKey = 'jwttoken'
const jwt = require('jsonwebtoken')
const User = require('../models/users')
const transporter = require('../services/mail')
require('dotenv').config();

/**
 * Registers a new user and sends a verification email.
 * 
 * @param {Object} req - The request object.
 * @param {Object} res - The response object.
 * @returns {void}
 */
const register = async (req, res) => {
    const { firstName, lastName, email, password, role } = req.body;

    if (!['customer', 'admin'].includes(role)) {
        return res.status(400).json({ message: 'Invalid role' });
    }

    try {
        // Check if the user already exists
        const existingUser = await User.findOne({ where: { email } });
        if (existingUser) {
            return res.status(400).json({ message: 'Email is already registered' });
        }

        // Hash the password
        const hashedPassword = bcrypt.hashSync(password, 8);

        // Create verification token
        const verificationToken = jwt.sign({ email, role: role }, secretOrPrivateKey, { expiresIn: '1h' });

        // Create user
        const userDetails = await User.create({
            firstName,
            lastName,
            email,
            password: hashedPassword,
            role,
            verificationToken
        });

        // Send verification email
        const localurl = 'http://localhost:3000'
        const mailOptions = {
            from: 'damaris81@ethereal.email',
            to: email,
            subject: 'Please verify your email',
            text: `Click the following link to verify your email: ${localurl}/verify?token=${verificationToken}`
        };

        transporter.sendMail(mailOptions, (err) => {
            if (err) {
                console.error('Error sending email:', err);
                return res.status(500).json({ message: 'Error sending verification email' });
            }

            res.status(200).json({ message: 'User registered successfully. Please check your email to verify your account.', data: userDetails });
        });
    } catch (err) {
        console.error('Error registering user:', err);
        res.status(500).json({ message: 'Error registering user' });
    }
};

/**
 * Verifies the user's email address using the provided token.
 * 
 * @param {Object} req - The request object.
 * @param {Object} res - The response object.
 * @returns {void}
 */
const verifyEmail = async (req, res) => {
    const { token } = req.body;
    try {
        const decoded = jwt.verify(token, secretOrPrivateKey);
        const user = await User.findOne({ where: { email: decoded.email, verificationToken: token } });
        if (!user) {
            return res.status(400).json({ message: 'Invalid token' });
        }
        user.isVerified = true;
        user.verificationToken = null;
        await user.save();

        res.status(200).json({ message: 'Email verified successfully' });
    } catch (err) {
        console.error('Error verifying email:', err);
        res.status(500).json({ message: 'Error verifying email' });
    }
};

/**
 * Logs in an admin portal.
 * 
 * @param {Object} req - The request object.
 * @param {Object} res - The response object.
 * @returns {void}
 */
const adminLogin = async (req, res) => {
    const { email, password } = req.body;
    try {
        const user = await User.findOne({ where: { email } });

        if (!user) {
            return res.status(400).json({ message: 'User not found' });
        }

        if (user.role !== 'admin') {
            return res.status(403).json({ message: 'You are not allowed to login from here' });
        }

        if (!user.isVerified) {
            return res.status(400).json({ message: 'Please verify your email first' });
        }

        const isPasswordValid = bcrypt.compareSync(password, user.password);
        if (!isPasswordValid) {
            return res.status(400).json({ message: 'Invalid password' });
        }

        const token = jwt.sign({ id: user.id, role: user.role }, secretOrPrivateKey, { expiresIn: '24h' });

        res.status(200).json({ message: 'Login successful', token });
    } catch (err) {
        console.error('Error logging in:', err);
        res.status(500).json({ message: 'Error logging in' });
    }
};

/**
 * common login user and admin both can login.
 * 
 * @param {Object} req - The request object.
 * @param {Object} res - The response object.
 * @returns {void}
 */
const login = async (req, res) => {
    const { email, password } = req.body;

    try {
        const user = await User.findOne({ where: { email } });

        if (!user) {
            return res.status(400).json({ message: 'User not found' });
        }

        if (!user.isVerified) {
            return res.status(400).json({ message: 'Please verify your email first' });
        }

        const isPasswordValid = bcrypt.compareSync(password, user.password);
        if (!isPasswordValid) {
            return res.status(400).json({ message: 'Invalid password' });
        }

        const token = jwt.sign({ id: user.id, role: user.role }, secretOrPrivateKey, { expiresIn: '24h' });

        res.status(200).json({ message: 'Login successful', token });
    } catch (err) {
        console.error('Error logging in:', err);
        res.status(500).json({ message: 'Error logging in' });
    }
};

module.exports = {
    register,
    verifyEmail,
    adminLogin,
    login
};
