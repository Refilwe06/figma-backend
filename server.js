require("dotenv").config();
const express = require("express");
const cors = require("cors");
require("./passport");

const app = express();
const auth = require("./routes/auth");

app.use(
  cors({
    origin: process.env.CLIENT_URL,
    methods: ["GET", "POST"],
    credentials: true
  })
);

app.use(express.json());

// Authentication routes
app.use('/auth', auth);

app.listen(process.env.PORT || 5000, () => {
  console.log("Server is running");
});
