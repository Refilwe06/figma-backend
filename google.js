const router = require('express').Router();
const passport = require('passport');

router.get('/login/failed', (req, res) => {
    res.status(401).send({
        error: true,
        msg: 'Login failed'
    })
})

router.get('/login/success', (req, res) => {
    console.log('Session ID:', req.sessionID);  // Logs session ID
    console.log('Session Data:', req.session);  // Logs entire session data
    console.log('Authenticated User:', req.user);  // Logs req.user if authenticated

    if (req.user) {
        res.send({
            msg: 'Logged in successfully',
            user: req.user
        });
    } else {
        res.status(401).send({ error: true, msg: 'Not Authorized' });
    }
});


router.get('/google/callback',
    passport.authenticate('google', { failureRedirect: '/login/failed', successRedirect: process.env.CLIENT_URL + '/profile' }));

router.get('/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

router.get('/logout', (req, res) => {
    req.logout();
    res.redirect(process.env.CLIENT_URL);
});

module.exports = router;