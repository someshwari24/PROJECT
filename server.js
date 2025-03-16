const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const bodyParser = require('body-parser');
const validator = require('validator');
const cors = require('cors');

const app = express();
const port = 3006;

// Enable CORS for frontend communication
app.use(cors());
app.use(bodyParser.json());

// MySQL Connection Pool
const db = mysql.createPool({
  connectionLimit: 10,
  host: 'localhost',
  user: 'root',
  password: 'Someshwari@24',
  database: 'Customer',
  port: 3306,
});

// Signup API
app.post('/signup', async (req, res) => {
  const { username, email, password } = req.body;

  if (!username || !email || !password) {
    return res.status(400).json({ message: 'All fields are required' });
  }

  if (!validator.isEmail(email)) {
    return res.status(400).json({ message: 'Invalid email format' });
  }

  if (password.length < 8) {
    return res.status(400).json({ message: 'Password must be at least 8 characters long' });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const sql = 'INSERT INTO users (username, email, password) VALUES (?, ?, ?)';

    db.query(sql, [username, email, hashedPassword], (err, result) => {
      if (err) {
        if (err.code === 'ER_DUP_ENTRY') {
          return res.status(400).json({ message: 'Email already exists' });
        }
        console.error('Error inserting user:', err);
        return res.status(500).json({ message: 'Server error' });
      }
      res.status(201).json({ message: 'User registered successfully' });
    });
  } catch (error) {
    console.error('Error hashing password:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Login API
app.post('/login', (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: 'Email and password are required' });
  }

  const sql = 'SELECT * FROM users WHERE email = ?';
  db.query(sql, [email], (err, results) => {
    if (err) {
      console.error('Database query error:', err);
      return res.status(500).json({ message: 'Server error' });
    }

    if (results.length === 0) {
      return res.status(401).json({ message: 'Invalid email or password' });
    }

    const user = results[0];

    bcrypt.compare(password, user.password, (err, passwordMatch) => {
      if (err) {
        console.error('Bcrypt error:', err);
        return res.status(500).json({ message: 'Server error' });
      }

      if (!passwordMatch) {
        return res.status(401).json({ message: 'Invalid email or password' });
      }

      res.status(200).json({ message: 'Login successful' });
    });
  });
});

// Keep MySQL Connection Alive (For Connection Pool)
setInterval(() => {
  db.getConnection((err, connection) => {
    if (err) {
      console.error('MySQL keep-alive error:', err);
      return;
    }
    connection.ping();
    connection.release();
  });
}, 30000);

// Start Server
app.listen(port, () => {
  console.log(`🚀 Server running on port ${port}`);
});
