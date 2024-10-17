require("dotenv").config();
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const passport = require("passport");
require("./passport");
const google = require("./google");
const db = require("./db");

const app = express();
const salt = 10;

app.use(
  cors({
    origin: process.env.CLIENT_URL,
    methods: ["GET", "POST"],
    credentials: true
  })
);

app.use(express.json());

// Middleware to verify JWT token
const verifyToken = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1]; // Get token from Authorization header
  if (!token) {
    return res.status(401).json({ err: 'Unauthorized' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(401).json({ err: 'Token expired or invalid' });
    }
    req.user = decoded; // Attach decoded token (user) to request
    next();
  });
};

app.post("/register", (req, res) => {
  const { password, name, email, rememberMe } = req.body;

  const sql = "INSERT INTO ruix_users (name, email, password) VALUES (?)";
  bcrypt.hash(password, salt, (err, hash) => {
    if (err) {
      return res.status(500).json({ err: "Error hashing password" }); // Changed to a 500 error
    }
    const values = [name, email, hash];
    db.query(sql, [values], (err, result) => {
      if (err) {
        console.error(err.stack);
        err.message = err.message.includes('Duplicate') ? 'Email already exists, please login' : err.message;
        return res.status(400).json({ err: err.message }); // Changed to a 400 error
      }
      const userQuery = "SELECT * FROM ruix_users WHERE user_id = ?";
      sendUserToClient(res, userQuery, result.insertId, "Registration successful!", rememberMe);
    });
  });
});

app.post("/login", (req, res) => {
  const { email, password } = req.body;

  const sql = "SELECT * FROM ruix_users WHERE email = ?";
  db.query(sql, [email], (err, data) => {
    if (err) return res.json({ err: "Login error in server" });
    if (data.length > 0) {
      const [user] = data;
      bcrypt.compare(password, user.password, (err, passwordMatches) => {
        if (err) return res.json({ err: "Incorrect credentials" });
        if (passwordMatches) {
          const token = jwt.sign({ user_id: user.user_id }, process.env.JWT_SECRET, {
            expiresIn: "1d",
          });
          delete user.password; // Don't send the password back
          return res.status(200).json({ msg: "Login successful!", user, token });
        } else {
          return res.status(400).json({ err: "Incorrect credentials" });
        }
      });
    } else {
      return res.status(400).json({ err: "Email not found" });
    }
  });
});

app.get("/logout", (req, res) => {
  // No cookie to clear, just return success message
  return res.status(200).json({ Status: "Success", Message: "You have been Logged Out!" });
});

// Function to send user object and message to client
const sendUserToClient = (res, query, id, msg, rememberMe = false) => {
  db.query(query, [id], (err, result) => {
    if (err) {
      console.error(err.stack);
      return res.status(400).json({ err: err.message });
    }
    const user = result[0];
    const token = jwt.sign({ user_id: user.user_id }, process.env.JWT_SECRET, {
      expiresIn: rememberMe ? "30d" : "1d",
    });
    delete user.password; // Don't send the password back
    return res.status(200).json({ msg, user, token });
  });
};

app.get('/get-user', verifyToken, (req, res) => {
  const { googleId } = req.user;
  console.log('Authenticated User:', req.user);  // log req.user if authenticated

  db.query('SELECT * FROM ruix_users WHERE google_id = ?', [googleId], (err, results) => {
    if (err) return res.status(400).json({ err: err.message });

    res.send({
      user: results[0],
    });
  });
});

// Google authentication routes
app.use('/auth', google);
app.use(verifyToken); // Middleware to protect routes

app.listen(process.env.PORT || 5000, () => {
  console.log("Server is running");
});
