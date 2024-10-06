require("dotenv").config();
const express = require("express");
const mysql = require("mysql2");
const cors = require("cors");
const bcrypt = require("bcrypt");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");

const salt = 10;

const app = express();
app.use(express.json());
app.use(
  cors({
    origin: "*",
    methods: ["GET", "POST"],
    credentials: true,
  })
);

app.use(cookieParser());

const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
})


db.connect((err) => {
  if (err) {
    console.error(err.stack)
  }
  console.log('Successfully connected to MySQL database');
});
const { verify } = jwt;


const verifyUser = (req, res, next) => {
  const token = req.cookies.token;
  if (!token) {
    return res.json({ err: "Session expires, please login" });
  } else {
    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
      if (err) {
        return res.json({ err: "Incorrect Token" });
      } else {
        req.name = decoded.name;
        next();
      }
    });
  }
};

app.post("/register", (req, res) => {
  console.log(req.body);
  const { password, name, email } = req.body;

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
      return res
        .status(200)
        .json({ msg: "Registration successful!" });
    });
  });
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
          console.log(passwordMatches);
          if (err) return res.json({ err: "Incorrect credentials" });
          if (passwordMatches) {
            const token = jwt.sign({ user_id: user.user_id }, process.env.JWT_SECRET, {
              expiresIn: "1d",
            });
            res.cookie("token", token, { httpOnly: true });
            delete user.password;
            return res
              .status(200)
              .json({ msg: "Login successful!", user });
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

app.listen(5000, () => {
  console.log("Server is running");
});