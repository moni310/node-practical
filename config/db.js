const { Sequelize } = require('sequelize');
const dotenv = require('dotenv');

dotenv.config();
const sequelize = new Sequelize(
  'node-project',
  'root',
  '1234567890',
  {
    host: 'localhost',
    port: 3307,
    dialect: 'mysql' || 'PostgreSQL',
    logging: false,
  }
);
module.exports = sequelize;
