const router = require('express').Router();
const passport = require('passport');
const JWT = require('jsonwebtoken')
router.get('/login/failed', (req, res) => {
    res.status(401).send({
        error: true,
        msg: 'Login failed'
    })
})

router.get('/login/success', (req, res) => {
    console.log('Session ID:', req.sessionID);  // log session ID
    console.log('Session Data:', req.session);  // log entire session data
    console.log('Authenticated User:', req.user);  // log req.user if authenticated

    if (req.user) {
        res.send({
            msg: 'Logged in successfully',
            user: req.user,
            token: req.cookies.token
        });
    } else {
        res.status(401).send({ error: true, msg: 'Not Authorized, Please Log In' });
    }
});

router.get('/google/callback', passport.authenticate('google', { failureRedirect: '/login' }), (req, res) => {
    // On successful login, generate a cookie and redirect
    const user = req.user; // User data returned from Google
    const token = JWT.sign(user.google_id, process.env.JWT_SECRET);
    // Set the cookie
    res.cookie('token', token, { httpOnly: false });

    // Redirect to the profile page
    res.redirect(process.env.CLIENT_URL + '/profile');
});
router.get('/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

router.get('/logout', (req, res) => {
    console.log('Before logout:', req.isAuthenticated());
    req.logout();
    res.clearCookie('token'); // Clear the cookie
    res.send({ msg: 'Logged out successfully' })
});



module.exports = router;