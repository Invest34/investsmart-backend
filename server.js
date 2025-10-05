require("dotenv").config(); // ✅ Load environment variables from .env

const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");

const app = express();
app.use(cors());
app.use(bodyParser.json());

// =========================
// ENV VARIABLES
// =========================
const PORT = process.env.PORT || 5000;
const SECRET_KEY = process.env.SECRET_KEY || "defaultsecret";
const BINANCE_WALLET = process.env.BINANCE_WALLET || "YOUR_BINANCE_WALLET_ADDRESS_HERE";

// =========================
// DATABASE CONNECTION (PostgreSQL)
// =========================
const db = new Pool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT || 5432,
  ssl: { rejectUnauthorized: false }, // ✅ Needed for Render
});

db.connect()
  .then(() => console.log(`✅ Connected to PostgreSQL database: ${process.env.DB_NAME}`))
  .catch(err => {
    console.error("❌ Database connection failed:", err.message);
    process.exit(1);
  });

// =========================
// MIDDLEWARE
// =========================
function verifyToken(req, res, next) {
  const bearerHeader = req.headers["authorization"];
  if (!bearerHeader)
    return res.status(401).json({ error: "Access denied. No token provided." });

  const token = bearerHeader.split(" ")[1];
  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    req.user = decoded;
    next();
  } catch {
    return res.status(401).json({ error: "Invalid or expired token" });
  }
}

// =========================
// AUTH ROUTES
// =========================
app.post("/auth/signup", async (req, res) => {
  const { full_name, email, phone, password } = req.body;
  if (!full_name || !email || !phone || !password)
    return res.status(400).json({ error: "All fields are required" });

  try {
    const hashedPassword = bcrypt.hashSync(password, 10);
    await db.query(
      "INSERT INTO users (full_name, email, phone, password) VALUES ($1, $2, $3, $4)",
      [full_name, email, phone, hashedPassword]
    );
    res.json({ message: "Signup successful ✅" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/auth/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    const { rows } = await db.query("SELECT * FROM users WHERE email = $1", [email]);
    if (rows.length === 0)
      return res.status(401).json({ error: "User not found" });

    const user = rows[0];
    const isPasswordValid = bcrypt.compareSync(password, user.password);
    if (!isPasswordValid)
      return res.status(401).json({ error: "Invalid password" });

    const token = jwt.sign({ id: user.id }, SECRET_KEY, { expiresIn: "1h" });
    res.json({ message: "Login successful ✅", token, user_id: user.id });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// =========================
// GET USER INFO
// =========================
app.get("/auth/user/:user_id", verifyToken, async (req, res) => {
  const { user_id } = req.params;
  try {
    const { rows } = await db.query(
      "SELECT id, full_name, email, phone FROM users WHERE id = $1",
      [user_id]
    );
    if (rows.length === 0)
      return res.status(404).json({ error: "User not found" });
    res.json(rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// =========================
// TRANSACTIONS
// =========================
app.post("/transactions/deposit", verifyToken, async (req, res) => {
  const { user_id, amount } = req.body;
  if (!user_id || !amount)
    return res.status(400).json({ error: "User ID and amount are required" });

  try {
    await db.query(
      "INSERT INTO transactions (user_id, type, amount, status) VALUES ($1, 'deposit', $2, 'pending')",
      [user_id, amount]
    );
    res.json({
      message:
        "Deposit request recorded. Please send the amount to the Binance wallet below.",
      wallet: BINANCE_WALLET,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/transactions/withdrawal", verifyToken, async (req, res) => {
  const { user_id, amount } = req.body;
  if (!user_id || !amount)
    return res.status(400).json({ error: "User ID and amount are required" });

  try {
    await db.query(
      "INSERT INTO transactions (user_id, type, amount, status) VALUES ($1, 'withdrawal', $2, 'pending')",
      [user_id, amount]
    );
    res.json({ message: "Withdrawal request recorded. Pending approval." });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get("/transactions/:user_id", verifyToken, async (req, res) => {
  const { user_id } = req.params;
  try {
    const { rows } = await db.query(
      "SELECT id, type, amount, status, date FROM transactions WHERE user_id = $1 ORDER BY date DESC",
      [user_id]
    );
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// =========================
// CONTACT ROUTE
// =========================
app.post("/contact", verifyToken, async (req, res) => {
  const { user_id, name, email, message } = req.body;
  if (!user_id || !name || !email || !message)
    return res.status(400).json({ error: "All fields are required" });

  try {
    await db.query(
      "INSERT INTO contacts (user_id, name, email, message) VALUES ($1, $2, $3, $4)",
      [user_id, name, email, message]
    );
    res.json({ message: "Message sent successfully ✅" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// =========================
// START SERVER
// =========================
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
