const express = require("express");
const mysql = require("mysql");
const cors = require("cors");
const bcrypt = require("bcrypt");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");

const salt = 10;

const app = express();
app.use(express.json());
app.use(
  cors({
    origin: "https://figma-backend-mm5f.onrender.com",
    methods: ["GET", "POST"],
    credentials: true,
  })
);

app.use(cookieParser());

const db = mysql.createConnection({
  host: "localhost",
  user: "newUser",
  password: "password",
  database: "signup",
});

const { verify } = jwt;

const verifyUser = (req, res, next) => {
  const token = req.cookies.token;
  if (!token) {
    return res.json({ Error: "WARNING: You have Not been Authenticated" });
  } else {
    jwt.verify(token, "jwt-secret-key", (err, decoded) => {
      if (err) {
        return res.json({ Error: "Incorrect Token" });
      } else {
        req.name = decoded.name;
        next();
      }
    });
  }
};

app.get("/", verifyUser, (req, res) => {
  return res.json({ Status: "Success", name: req.name });
});

app.post("/register", (req, res) => {
  const sql = "INSERT INTO login (⁠ name ⁠, ⁠ email ⁠, ⁠ password ⁠) VALUES (?)";
  bcrypt.hash(req.body.password.toString(), salt, (err, hash) => {
    if (err) {
      return res.status(500).json({ Error: "Error hashing password" }); // Changed to a 500 error
    }
    const values = [req.body.name, req.body.email, hash];
    // Insert user data into the database
    db.query(sql, [values], (err, result) => {
      if (err) {
        return res.status(400).json({ Error: "Data Input Error into Server" }); // Changed to a 400 error
      }
      // Return success message if registration is successful
      return res
        .status(200)
        .json({ Status: "Success", Message: "Registration successful!" });
    });
  });
});

app.post("/login", (req, res) => {
  console.log(req.body);
  const sql = "SELECT * FROM login WHERE email = ?";
  db.query(sql, [req.body.email], (err, data) => {
    if (err) return res.json({ Error: "Login error in server" });
    if (data.length > 0) {
      bcrypt.compare(
        req.body.password.toString(),
        data[0].password,
        (err, response) => {
          if (err) return res.json({ Error: "Password hash error" });
          if (response) {
            const name = data[0].name;
            const token = jwt.sign({ name }, "jwt-secret-key", {
              expiresIn: "1d",
            });
            res.cookie("token", token);
            return res
              .status(200)
              .json({ Status: "Success", Message: "Login successful!" });
          } else {
            return res.json({
              Error: "You have entered an Incorrect Password",
            });
          }
        }
      );
    } else {
      return res.json({ Error: "Email not found" });
    }
  });
});

app.get("/logout", (req, res) => {
  res.clearCookie("token");
  return res
    .status(200)
    .json({ Status: "Success", Message: "You have been Logged Out!" });
});

app.listen(3000, () => {
  console.log("Server is running");
});