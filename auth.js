const fs = require("fs");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");

class Auth {
  constructor(options = {}) {
    this.users = {};
    this.secretKey =
      options.secretKey || crypto.randomBytes(32).toString("hex");
    this.tokenExpiration = options.tokenExpiration || "1h";
    this.saltRounds = options.saltRounds || 10;
    this.logFile = options.logFile || "auth.log";
    this.logger = this.createLogger(this.logFile);
  }

  register(username, password) {
    const hashedPassword = this.hashPassword(password);
    this.users[username] = hashedPassword;
    this.saveUsersToFile();
    this.logger.info(`User '${username}' registered.`);
  }

  login(username, password) {
    const hashedPassword = this.users[username];
    if (!hashedPassword) {
      this.logger.warn(`User '${username}' not found.`);
      return false;
    }
    const isMatch = this.comparePassword(password, hashedPassword);
    if (!isMatch) {
      this.logger.warn(`Invalid password for user '${username}'.`);
    } else {
      this.logger.info(`User '${username}' logged in.`);
    }
    return isMatch;
  }

  hashPassword(password) {
    return bcrypt.hashSync(password, this.saltRounds);
  }

  comparePassword(password, hashedPassword) {
    return bcrypt.compareSync(password, hashedPassword);
  }

  saveUsersToFile(filename = "users.json") {
    const data = JSON.stringify(this.users, null, 2); // Pretty-print JSON
    fs.writeFileSync(filename, data);
  }

  loadUsersFromFile(filename = "users.json") {
    try {
      const data = fs.readFileSync(filename);
      this.users = JSON.parse(data);
      this.logger.info("Users loaded from file.");
    } catch (error) {
      this.logger.error(`Error loading users: ${error.message}`);
    }
  }

  generateToken(payload) {
    return jwt.sign(payload, this.secretKey, {
      expiresIn: this.tokenExpiration,
    });
  }

  verifyToken(token) {
    try {
      return jwt.verify(token, this.secretKey);
    } catch (error) {
      this.logger.error(`Invalid token: ${error.message}`);
      return null;
    }
  }

  createLogger(logFile) {
    const logger = winston.createLogger({
      transports: [new winston.transports.File({ filename: logFile })],
    });
    return logger;
  }
}

module.exports = Auth;
