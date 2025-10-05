const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const mysql = require("mysql2");

const app = express();
app.use(cors());
app.use(bodyParser.json());

const SECRET_KEY = "mysecretkey";
const BINANCE_WALLET = "YOUR_BINANCE_WALLET_ADDRESS_HERE"; // <-- Replace with your wallet

// =========================
// DATABASE CONNECTION
// =========================
const db = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "Brian23@",
  database: "investapro"
});

db.connect(err => {
  if (err) {
    console.error("❌ Database connection failed:", err.message);
    process.exit(1);
  }
  console.log("✅ Connected to MySQL database");
});

// =========================
// MIDDLEWARE
// =========================
function verifyToken(req, res, next) {
  const bearerHeader = req.headers["authorization"];
  if (!bearerHeader) return res.status(401).json({ error: "Access denied. No token provided." });
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
app.post("/auth/signup", (req, res) => {
  const { full_name, email, phone, password } = req.body;
  if (!full_name || !email || !phone || !password) return res.status(400).json({ error: "All fields are required" });

  const hashedPassword = bcrypt.hashSync(password, 10);
  db.query(
    "INSERT INTO users (full_name, email, phone, password) VALUES (?, ?, ?, ?)",
    [full_name, email, phone, hashedPassword],
    err => {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ message: "Signup successful ✅" });
    }
  );
});

app.post("/auth/login", (req, res) => {
  const { email, password } = req.body;
  db.query("SELECT * FROM users WHERE email = ?", [email], (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    if (results.length === 0) return res.status(401).json({ error: "User not found" });

    const user = results[0];
    const isPasswordValid = bcrypt.compareSync(password, user.password);
    if (!isPasswordValid) return res.status(401).json({ error: "Invalid password" });

    const token = jwt.sign({ id: user.id }, SECRET_KEY, { expiresIn: "1h" });
    res.json({ message: "Login successful ✅", token, user_id: user.id });
  });
});

// =========================
// GET USER INFO (for dashboard welcome)
// =========================
app.get("/auth/user/:user_id", verifyToken, (req, res) => {
  const { user_id } = req.params;
  db.query("SELECT id, full_name, email, phone FROM users WHERE id = ?", [user_id], (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    if (results.length === 0) return res.status(404).json({ error: "User not found" });
    res.json(results[0]);
  });
});

// =========================
// TRANSACTIONS / INVESTMENTS
// =========================
app.post("/transactions/deposit", verifyToken, (req, res) => {
  const { user_id, amount } = req.body;
  if (!user_id || !amount) return res.status(400).json({ error: "User ID and amount are required" });

  db.query(
    "INSERT INTO transactions (user_id, type, amount, status) VALUES (?, 'deposit', ?, 'pending')",
    [user_id, amount],
    (err) => {
      if (err) return res.status(500).json({ error: err.message });

      res.json({
        message: "Deposit request recorded. Please send the amount to the Binance wallet below.",
        wallet: BINANCE_WALLET
      });
    }
  );
});

app.post("/transactions/withdrawal", verifyToken, (req, res) => {
  const { user_id, amount } = req.body;
  if (!user_id || !amount) return res.status(400).json({ error: "User ID and amount are required" });

  db.query(
    "INSERT INTO transactions (user_id, type, amount, status) VALUES (?, 'withdrawal', ?, 'pending')",
    [user_id, amount],
    (err) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ message: "Withdrawal request recorded. Pending approval." });
    }
  );
});

app.get("/transactions/:user_id", verifyToken, (req, res) => {
  const { user_id } = req.params;

  db.query(
    "SELECT id, type, amount, status, date FROM transactions WHERE user_id = ? ORDER BY date DESC",
    [user_id],
    (err, results) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json(results);
    }
  );
});

// =========================
// USER INVESTMENTS / PORTFOLIO
// =========================
app.get("/invest/:user_id", verifyToken, (req, res) => {
  const { user_id } = req.params;

  db.query(
    `SELECT i.id, p.name, i.amount, i.start_date 
     FROM investments i 
     JOIN plans p ON i.plan_id = p.id 
     WHERE i.user_id = ?`,
    [user_id],
    (err, investmentResults) => {
      if (err) return res.status(500).json({ error: err.message });

      db.query(
        `SELECT id, type, amount, date 
         FROM transactions 
         WHERE user_id = ? AND type='withdrawal'`,
        [user_id],
        (err2, transactionResults) => {
          if (err2) return res.status(500).json({ error: err2.message });

          const formattedWithdrawals = transactionResults.map(t => ({
            id: t.id,
            name: "Withdrawal",
            amount: -t.amount,
            created_at: t.date
          }));

          const allRecords = [...investmentResults, ...formattedWithdrawals];
          res.json(allRecords);
        }
      );
    }
  );
});

// =========================
// CONTACT ROUTE
// =========================
app.post("/contact", verifyToken, (req, res) => {
  const { user_id, name, email, message } = req.body;
  if (!user_id || !name || !email || !message) return res.status(400).json({ error: "All fields are required" });

  db.query(
    "INSERT INTO contacts (user_id, name, email, message) VALUES (?, ?, ?, ?)",
    [user_id, name, email, message],
    err => {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ message: "Message sent successfully ✅" });
    }
  );
});

// =========================
// START SERVER
// =========================
const PORT = 5000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
