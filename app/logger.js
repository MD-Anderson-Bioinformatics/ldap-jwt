const bunyan = require("bunyan");
const bformat = require("bunyan-format");
const formatOut = bformat({ outputMode: "long", color: process.env.COLORIZE_LOGS?.toLowerCase() === "true" });

const logger = bunyan.createLogger({
  // also used for logging in ldapauth-fork and ldapjs
  name: "ldap-jwt",
  level: process.env.LOG_LEVEL || "info",
  stream: formatOut
});

module.exports = logger;
