require("dotenv").config();
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");
const passport = require("passport");
require("./passport");
const google = require("./google");
const db = require("./db");
const cookieSession = require("cookie-session");
const salt = 10;

const app = express();
app.use(express.json());

app.use(cookieParser());

app.use(
  cookieSession({
    secret: process.env.JWT_SECRET,
    name: 'session',
    keys: ['ruix'],
    maxAge: 24 * 60 * 60 * 1000
  })
)

app.use(passport.initialize());
app.use(passport.session());
app.use(
  cors({
    origin: process.env.CLIENT_URL,
    methods: ["GET", "POST"],
    credentials: true
  })
);

const verifyToken = (req, res, next) => {
  const token = req.cookies.token; // assuming cookie-parser is used
  if (!token) {
    return res.status(401).json({ message: 'Unauthorized' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(401).json({ message: 'Token expired or invalid' });
    }
    req.user = decoded; // attach decoded token (user) to request
    next();
  });
};


app.post("/register", (req, res) => {
  const { password, name, email, rememberMe } = req.body;

  const sql = "INSERT INTO users (name, email, password) VALUES (?)";
  bcrypt.hash(password, salt, (err, hash) => {
    if (err) {
      return res.status(500).json({ err: "Error hashing password" }); // Changed to a 500 error
    }
    const values = [name, email, hash];
    // Insert user data into the database
    db.query(sql, [values], (err, result) => {
      if (err) {
        console.error(err.stack);
        // Return error message if registration fails
        err.message = err.message.includes('Duplicate') ? 'Email already exists, please login' : err.message;
        return res.status(400).json({ err: err.message }); // Changed to a 400 error
      }
      // Return success message if registration is successful
      const userQuery = "SELECT * FROM users WHERE user_id = ?";
      sendUserToClient(res, userQuery, result.insertId, "Registration successful!");
    });
  })
});

app.post("/login", (req, res) => {
  const { email, password } = req.body;

  const sql = "SELECT * FROM users WHERE email = ?";
  db.query(sql, [email], (err, data) => {
    if (err) return res.json({ err: "Login error in server" });
    if (data.length > 0) {
      const [user] = data;
      bcrypt.compare(
        password,
        user.password,
        (err, passwordMatches) => {
          if (err) return res.json({ err: "Incorrect credentials" });
          if (passwordMatches) {
            const token = jwt.sign({ user_id: user.user_id }, process.env.JWT_SECRET, {
              expiresIn: "1d",
            });
            res.cookie("token", token, { httpOnly: false });
            delete user.password;
            return res
              .status(200)
              .json({ msg: "Login successful!", user, token });
          } else {
            return res.status(400).json({
              err: "Incorrect credentials",
            });
          }
        }
      );
    } else {
      return res.status(400).json({ err: "Email not found" });
    }
  });
});

app.get("/logout", (req, res) => {
  res.clearCookie("token");
  return res
    .status(200)
    .json({ Status: "Success", Message: "You have been Logged Out!" });
});

// Reusable function to send user object and message to client
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
    res.cookie("token", token, { httpOnly: false });
    delete user.password;
    return res
      .status(200)
      .json({ msg, user, token });
  });
};

app.use('/auth', google);
app.use(verifyToken);


app.listen(process.env.PORT || 5000, () => {
  console.log("Server is running");
});
