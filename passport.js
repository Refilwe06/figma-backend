const GoogleStrategy = require('passport-google-oauth20').Strategy;
const passport = require('passport');
const db = require("./db");

passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: process.env.SERVER_URL + "/auth/google/callback",
    scope: ['https://www.googleapis.com/auth/userinfo.email', 'https://www.googleapis.com/auth/userinfo.profile']
},
    function (accessToken, refreshToken, profile, cb) {
        const { name, email } = profile._json;

        db.query('SELECT * FROM users WHERE google_id = ?', [profile.id], (err, results) => {
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

                db.query('INSERT INTO users SET ?', newUser, (err, result) => {
                    if (err) return cb(err);
                    newUser.id = result.insertId;
                    return cb(null, newUser);
                });
            }
        });

    }
));

// Create a session using the unique google_id
passport.serializeUser((user, done) => {
    process.nextTick(function () {
        return done(null, user.google_id);
    });
});

// Deserialize user from session (retrieve user from DB)
passport.deserializeUser((id, done) => {
    db.query('SELECT * FROM users WHERE google_id = ?', [id], (err, results) => {
        if (err) return done(err);

        if (results.length === 0) return done(null, false);  // No user found
        return done(null, results[0]);  // Return user object
    });
});
