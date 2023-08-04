const winston = require('winston');

/*
  This is a very rough interface to the winston logging package.
  There are many opportunities for improvement.
*/

const logger = winston.createLogger({
  level: (process.env.LOG_LEVEL || 'info'),
  format: winston.format.combine(
    winston.format.colorize(),
    winston.format.json(),
    winston.format.timestamp({format: 'DD-MMM-YYYY HH:mm:ss'}),
    winston.format.printf(info => `${info.timestamp} ${info.level}: ${info.message}`),
  ),
  transports: [
    new winston.transports.Console(),
  ],
});

module.exports = logger;


