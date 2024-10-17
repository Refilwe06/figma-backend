// Middleware to verify JWT token
const jwt = require('jsonwebtoken');
const verifyToken = (req, res, next) => {
    const token = req.headers.authorization?.split(" ")[1]; // Get token from Authorization header
    if (!token) {
        return res.status(401).json({ err: 'Unauthorized' });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(401).json({ err: 'Token expired or invalid' });
        }
        req.user = decoded; // Attach decoded token (user) to request
        next();
    });
};

module.exports = verifyToken;