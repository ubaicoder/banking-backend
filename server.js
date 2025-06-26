const express = require("express");
const mysql = require("mysql2/promise");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const cors = require("cors");
require("dotenv").config();

const app = express();
const port = process.env.PORT;

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors());

let db;
// Memory-based token storage
const inMemoryTokens = {};

const setupDatabase = async () => {
  // Connect to MySQL
  const connection = await mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
  });

  // Create and use the database
  await connection.query(
    `CREATE DATABASE IF NOT EXISTS ${process.env.DB_NAME}`
  );
  await connection.query(`USE ${process.env.DB_NAME}`);

  // Create Users table
  await connection.query(`
    CREATE TABLE IF NOT EXISTS Users (
      id INT AUTO_INCREMENT PRIMARY KEY,
      username VARCHAR(30) NOT NULL UNIQUE,
      password VARCHAR(255) NOT NULL,
      role ENUM('customer', 'banker') NOT NULL
    )
  `);

  // Create Accounts table
  await connection.query(`
    CREATE TABLE IF NOT EXISTS Accounts (
      id INT AUTO_INCREMENT PRIMARY KEY,
      user_id INT NOT NULL,
      type ENUM('deposit', 'withdrawal') NOT NULL,
      amount DECIMAL(10, 2) NOT NULL,
      balance DECIMAL(10, 2) NOT NULL,
      FOREIGN KEY (user_id) REFERENCES Users(id) ON DELETE CASCADE
    )
  `);

  db = connection;
  console.log(" Database setup complete");
};

// Start server after DB is ready
setupDatabase().then(() => {
  app.listen(port, () => {
    console.log(` Server is running on http://localhost:${port}`);
  });
});

// Signup Route
app.post("/signup", async (req, res) => {
  console.log(" Signup request:", req.body);
  const { username, password, role } = req.body;

  if (!username || !password || !role) {
    return res.status(400).json({ message: "All fields are required" });
  }

  try {
    const hashed = await bcrypt.hash(password, 8);

    await db.query(
      `INSERT INTO Users (username, password, role) VALUES (?, ?, ?)`,
      [username, hashed, role]
    );

    res.status(200).json({ message: "User registered successfully" });
  } catch (err) {
    console.error("Signup error:", err);
    if (err.code === "ER_DUP_ENTRY") {
      return res.status(400).json({ message: "Username already exists" });
    }
    res.status(500).json({ message: "Server error. Please try again." });
  }
});

// In MySQL, ENUM is a data type that allows you to define a column which can only contain specific predefined values — like a multiple-choice list.

// Middleware to authenticate token
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader?.split(" ")[1];

  if (!token || !inMemoryTokens[token]) {
    return res
      .status(401)
      .json({ message: "Unauthorized: Invalid or missing token" });
  }

  req.user = inMemoryTokens[token]; // set user info
  next();
}

//  Login Route
app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  console.log(" Login request:", req.body);
  if (!username || !password) {
    return res
      .status(400)
      .json({ message: "Username and password are required" });
  }
  try {
    const [rows] = await db.query(`SELECT * FROM Users WHERE username = ?`, [
      username,
    ]);
    if (rows.length === 0) {
      return res.status(404).json({ message: "User not found" });
    }
    const user = rows[0];
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ message: "Invalid credentials" });
    }
    // Token generation
    const token = crypto.randomBytes(32).toString("hex");
    inMemoryTokens[token] = {
      id: user.id,
      username: user.username,
      role: user.role,
    };
    res.status(200).json({ message: "Login successful", user, token }); // res.json only takes one argument.
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ message: "Server error. Please try again." });
  }
});
// Token authentication route
app.get("/protected", authenticateToken, (req, res) => {
  res.json({
    id: req.user.id,
    username: req.user.username,
    role: req.user.role,
  });
});

// ✅ Deposit Route
app.post("/deposit", async (req, res) => {
  const { userId, amount } = req.body;
  if (!userId || !amount) return res.status(400).send("Missing data.");

  const [last] = await db.query(
    "SELECT balance FROM Accounts WHERE user_id = ? ORDER BY id DESC LIMIT 1",
    [userId]
  );
  const prevBalance = last.length > 0 ? last[0].balance : 0;
  const newBalance = parseFloat(prevBalance) + parseFloat(amount);

  await db.query(
    "INSERT INTO Accounts (user_id, type, amount, balance) VALUES (?, 'deposit', ?, ?)",
    [userId, amount, newBalance]
  );

  res.send(" Deposit successful. New balance: " + newBalance);
});

// ✅ Withdraw Route
app.post("/withdraw", async (req, res) => {
  const { userId, amount } = req.body;
  if (!userId || !amount) return res.status(400).send("Missing data.");

  const [last] = await db.query(
    "SELECT balance FROM Accounts WHERE user_id = ? ORDER BY id DESC LIMIT 1",
    [userId]
  );
  const prevBalance = last.length > 0 ? last[0].balance : 0;

  if (parseFloat(amount) > parseFloat(prevBalance)) {
    return res.status(400).send(" Insufficient funds.");
  }

  const newBalance = parseFloat(prevBalance) - parseFloat(amount);

  await db.query(
    "INSERT INTO Accounts (user_id, type, amount, balance) VALUES (?, 'withdrawal', ?, ?)",
    [userId, amount, newBalance]
  );

  res.send(" Withdrawal successful. New balance: " + newBalance);
});

//  View Transactions Route
app.get("/transactions/:userId", async (req, res) => {
  const userId = req.params.userId;

  const [rows] = await db.query(
    "SELECT * FROM Accounts WHERE user_id = ? ORDER BY id DESC",
    [userId]
  );

  res.json(rows);
});

// Fetch data for banker
app.get("/fetch", async (req, res) => {
  console.log("hii i am here");
  try {
    const [rows] = await db.query(`SELECT * FROM Users where role = 'customer'`);
    res.json(rows);
  } catch (err) {
    console.error("Error fetching users:", err);
    res.json({ message: "Server error while fetching users" });
  }
});
