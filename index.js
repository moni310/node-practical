// require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const mysql = require('mysql2');

require('dotenv').config();  // Load environment variables

const app = express();
const port = 3000;

require('dotenv').config();
app.use(bodyParser.json());

// Routes
const userRoute = require('./routes/userRoutes');

app.use('/api/user/', userRoute);



app.listen(port, () => {
    console.log(`Server started on port ${port}`);
});
