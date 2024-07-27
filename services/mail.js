const nodemailer = require('nodemailer');
const dotenv = require('dotenv');

dotenv.config();
const transporter = nodemailer.createTransport({
    host: 'smtp.ethereal.email',
    port: 587,
    auth: {
        user: 'gina.huel73@ethereal.email',
        pass: 'ppC7Dpw1MHuGSXNZud'
    }
});

module.exports = transporter;
