# AuthKit

AuthKit is a powerful and feature-rich authentication library for Node.js. It provides a comprehensive set of functionalities for user registration, authentication, token generation, password hashing, and logging.

## Features

- User registration with secure password hashing
- User authentication with bcrypt password comparison
- Token generation and verification using JSON Web Tokens (JWT)
- Customizable options for secret key, token expiration, salt rounds, log file, etc.
- Logging functionality to record user registration, logins, warnings, and errors

## Installation

To use AuthKit in your project, import the auth.js.

## Usage

```javascript
// Create an instance of the Auth class
const auth = new Auth({
  secretKey: "your_secret_key", // Optional: Default is a randomly generated key
  tokenExpiration: "1h", // Optional: Default is '1h'
  saltRounds: 10, // Optional: Default is 10
  logFile: "auth.log", // Optional: Default is 'auth.log'
});

// Register a new user
auth.register("username", "password");

// Authenticate a user
const isAuthenticated = auth.login("username", "password");
if (isAuthenticated) {
  console.log("User authenticated successfully.");
} else {
  console.log("Authentication failed.");
}

// Generate and verify a token
const token = auth.generateToken({ userId: "username" });
const decodedToken = auth.verifyToken(token);
if (decodedToken) {
  console.log("Token is valid.");
} else {
  console.log("Token is invalid.");
}
```

## API

### `register(username, password)`

Registers a new user with the given username and password.

### `login(username, password)`

Authenticates a user with the provided username and password. Returns `true` if authentication is successful, `false` otherwise.

### `generateToken(payload)`

Generates a JSON Web Token (JWT) using the provided payload.

### `verifyToken(token)`

Verifies the validity of a JWT token. Returns the decoded token if valid, `null` otherwise.

## Options

- `secretKey`: Secret key used for token generation and verification. Default is a randomly generated key.
- `tokenExpiration`: Expiration time for JWT tokens. Default is '1h'.
- `saltRounds`: Number of bcrypt salt rounds for password hashing. Default is 10.
- `logFile`: File path for logging user registration, logins, warnings, and errors. Default is 'auth.log'.
