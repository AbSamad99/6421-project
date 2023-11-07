// Import necessary libraries
const express = require("express");
const bodyParser = require("body-parser");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");
require("dotenv").config();

// Create an Express application
const app = express();

// Set the API's listening port
const port = 3000;

// Use middleware to parse JSON data in requests
app.use(bodyParser.json());

// Create a PostgreSQL connection pool using environment variables
const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_DATABASE,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
});

// Signup
app.post("/signup", async (req, res) => {
  // Extract data
  const { firstName, lastName, email, password, dateOfBirth, address } =
    req.body;

  // Check if required data fields are provided
  if (
    !firstName ||
    !lastName ||
    !email ||
    !password ||
    !dateOfBirth ||
    !address
  ) {
    return res.status(400).send("Invalid request");
  }

  // Check if the email already exists
  const query1 = {
    text: "SELECT * FROM users WHERE email = $1",
    values: [email],
  };
  try {
    const result = await pool.query(query1);
    if (result.rows.length !== 0) {
      return res.status(400).send("Invalid request");
    }
  } catch (error) {
    console.log(error);
  }

  // Hash the password
  const hashedPassword = await bcrypt.hash(password, 10);

  // Store in the database
  const query = {
    text: "INSERT INTO users (first_name, last_name, email, password, date_of_birth, address) VALUES ($1, $2, $3, $4, $5, $6)",
    values: [firstName, lastName, email, hashedPassword, dateOfBirth, address],
  };

  // Return response
  try {
    await pool.query(query);
    res.status(201).send("User created");
  } catch (error) {
    console.error(error);
    res.status(500).send("Error creating user");
  }
});

// Signin
app.post("/signin", async (req, res) => {
  // Extract data
  const { email, password } = req.body;

  // Check if required fields are provided
  if (!email || !password) {
    return res.status(400).send("Invalid request");
  }

  // Check if the email already exists
  const query = {
    text: "SELECT * FROM users WHERE email = $1",
    values: [email],
  };
  try {
    const result = await pool.query(query);
    if (result.rows.length === 0) {
      return res.status(400).send("Invalid request");
    }

    // Retrieve the user
    const user = result.rows[0];

    // Password validity check
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(400).send("Invalid password");
    }

    // Generate JWT token
    const token = jwt.sign(
      { userId: user.id, email: user.email },
      process.env.JWT_KEY,
      { expiresIn: "1h" }
    );

    // Return response
    res.status(200).json({ token });
  } catch (error) {
    console.error(error);
    res.status(500).send("Authentication error");
  }
});

// Protected
app.get("/protectedRoute", (req, res) => {
  // Get JWT
  const token = req.headers.authorization;

  // Token check
  if (!token) {
    return res.status(401).send("Unauthorized");
  }

  // Verify JWT
  const jwt_token = token.split(" ")[1];
  jwt.verify(jwt_token, process.env.JWT_KEY, (err, decoded) => {
    if (err) {
      return res.status(401).send("Unauthorized");
    }

    const randomData = {
      message: "This is protected data",
      data: Math.random(),
    };

    // Return response
    res.status(200).send(randomData);
  });
});

// Update Password
app.post("/updatePassword", async (req, res) => {
  // Get JWT
  const token = req.headers.authorization;

  // Token checks
  if (!token) {
    return res.status(401).send("Unauthorized");
  }

  const jwt_token = token.split(" ")[1];

  const { currentPassword, newPassword } = req.body;

  // Check if required fields are provided
  if (!currentPassword || !newPassword) {
    return res.status(400).send("Invalid request");
  }

  // Verify JWT
  jwt.verify(jwt_token, process.env.JWT_KEY, async (err, decoded) => {
    if (err) {
      return res.status(401).send("Unauthorized");
    }

    const { email } = decoded;

    // Fetch user
    const querySelect = {
      text: "SELECT * FROM users WHERE email = $1",
      values: [email],
    };

    try {
      const result = await pool.query(querySelect);

      if (result.rows.length === 0) {
        return res.status(400).send("Invalid request");
      }

      const user = result.rows[0];

      // Check password
      const isPasswordValid = await bcrypt.compare(
        currentPassword,
        user.password
      );

      if (!isPasswordValid) {
        return res.status(400).send("Invalid request");
      }

      const newHashedPassword = await bcrypt.hash(newPassword, 10);

      // Update password
      const queryUpdate = {
        text: "UPDATE users SET password = $1 WHERE email = $2",
        values: [newHashedPassword, email],
      };

      await pool.query(queryUpdate);

      // Return response
      res.status(200).send("Password updated successfully");
    } catch (error) {
      console.error(error);
      res.status(500).send("Password update error");
    }
  });
});

// Start Listener
app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
