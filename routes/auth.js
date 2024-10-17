const router = require('express').Router();
const passport = require('passport');
const JWT = require('jsonwebtoken');
const bcrypt = require("bcrypt");
const db = require("../db");
const verifyToken = require('../middleware/authMiddleware');


// Endpoint for login failure
router.get('/login/failed', (req, res) => {
    res.status(401).send({
        error: true,
        msg: 'Login failed'
    });
});

// Google OAuth callback
router.get('/google/callback', passport.authenticate('google', { failureRedirect: '/login' }), (req, res) => {
    const jwt_token = JWT.sign({ googleId: req.user.google_id }, process.env.JWT_SECRET, { expiresIn: '1d' });

    res.redirect(`${process.env.CLIENT_URL}/profile?token=${jwt_token}`); // Redirect with token as query parameter
});


// Initiate Google OAuth
router.get('/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

// Register new user
router.post("/register", (req, res) => {
    const { password, name, email, rememberMe } = req.body;
    db.query(`SELECT user_id FROM ruix_users WHERE email = '${email}'`, (err, users) => {
        console.log(users.length);
        if (err) return res.status(500).json({ err: err.message });
        if (users.length) return res.status(409).send({ err: 'User already exists' });

        const sql = "INSERT INTO ruix_users (name, email, password) VALUES (?)";
        bcrypt.hash(password, 10, (err, hash) => {
            if (err) return res.status(500).json({ err: "Error hashing password" }); // Changed to a 500 error 
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
});

//  Log existing user in
router.post("/login", (req, res) => {
    const { email, password } = req.body;

    const sql = "SELECT * FROM ruix_users WHERE email = ?";
    db.query(sql, [email], (err, data) => {
        if (err) return res.status(500).json({ err: "Login error in server" });
        if (data.length > 0) {
            const [user] = data;
            bcrypt.compare(password, user.password, (err, passwordMatches) => {
                if (err) return res.status(400).json({ err: "Incorrect credentials" });
                if (passwordMatches) {
                    const token = JWT.sign({ user_id: user.user_id }, process.env.JWT_SECRET, {
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

// Function to send user object and message to client
const sendUserToClient = (res, query, id, msg, rememberMe = false) => {
    db.query(query, [id], (err, result) => {
        if (err) {
            console.error(err.stack);
            return res.status(400).json({ err: err.message });
        }
        const user = result[0];
        const token = JWT.sign({ user_id: user.user_id }, process.env.JWT_SECRET, {
            expiresIn: rememberMe ? "30d" : "1d",
        });
        delete user.password; // Don't send the password back
        return res.status(200).json({ msg, user, token });
    });
};

// Get user using signed token
router.get('/get-user', verifyToken, (req, res) => {
    const { googleId } = req.user;
    console.log('Authenticated User:', req.user);  // log req.user if authenticated

    db.query('SELECT * FROM ruix_users WHERE google_id = ?', [googleId], (err, results) => {
        if (err) return res.status(400).json({ err: err.message });

        res.send({
            user: results[0],
        });
    });
});



module.exports = router;
