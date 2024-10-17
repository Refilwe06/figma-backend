const router = require('express').Router();
const passport = require('passport');
const JWT = require('jsonwebtoken');

// Endpoint for login failure
router.get('/login/failed', (req, res) => {
    res.status(401).send({
        error: true,
        msg: 'Login failed'
    });
});

// Google OAuth callback
router.get('/google/callback', passport.authenticate('google', { failureRedirect: '/login' }), (req, res) => {
    const jwt_token = JWT.sign({ googleId: req.user.google_id }, process.env.JWT_SECRET, { expiresIn: '10s' });

    res.redirect(`${process.env.CLIENT_URL}/profile?token=${jwt_token}`); // Redirect with token as query parameter
});


// Initiate Google OAuth
router.get('/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

// Logout route
router.get('/logout', (req, res) => {
    res.send({ msg: 'Logged out successfully' });
});

module.exports = router;
