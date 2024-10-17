const GoogleStrategy = require('passport-google-oauth20').Strategy;
const passport = require('passport');
const jwt = require('jsonwebtoken'); // Import JWT
const db = require("./db");

passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: process.env.SERVER_URL + "/auth/google/callback",
    scope: ['https://www.googleapis.com/auth/userinfo.email', 'https://www.googleapis.com/auth/userinfo.profile']
},
    function (accessToken, refreshToken, profile, cb) {
        const { name, email } = profile._json;

        db.query('SELECT * FROM ruix_users WHERE google_id = ?', [profile.id], (err, results) => {
            if (err) return cb(err);

            if (results.length > 0) {
                // User found, return the user object
                return cb(null, results[0]);
            } else {
                // User not found, insert the new user into the DB
                const newUser = {
                    google_id: profile.id,
                    name,
                    email
                };

                db.query('INSERT INTO ruix_users SET ?', newUser, (err, result) => {
                    if (err) return cb(err);
                    newUser.id = result.insertId;
                    return cb(null, newUser);
                });
            }
        });

    }
));

// Instead of serializeUser and deserializeUser, generate a JWT upon successful login
passport.serializeUser((user, done) => {
    // Sign the JWT token with user details
    const token = jwt.sign(
        { google_id: user.google_id, name: user.name, email: user.email },
        process.env.JWT_SECRET,
        { expiresIn: '1d' } // Token valid for 1 day
    );
    return done(null, token); // Pass the token instead of the user ID
});

passport.deserializeUser((token, done) => {
    // No need to deserialize, as JWT carries the payload
    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) return done(err, false); // Invalid token
        return done(null, decoded); // Pass the decoded token (user data)
    });
});
