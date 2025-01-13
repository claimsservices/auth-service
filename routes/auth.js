const express = require('express');
const cors = require('cors'); // Import the cors module
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const db = require('../db');
const router = express.Router();
const validator = require('validator');

// Enable CORS globally for all routes
router.use(cors({
    origin: 'http://192.168.1.120:3000', // Allow requests from your frontend origin
    methods: ['GET', 'POST', 'PUT', 'DELETE'], // Allow specific HTTP methods
    allowedHeaders: ['Content-Type', 'Authorization'], // Allow specific headers
}));

// Register
router.post('/register', async (req, res) => {
    const { username, password, email, first_name, last_name, phone } = req.body;

    // Validation checks
    if (!username || !password || !email) {
        return res.status(400).json({ message: 'Username, email, and password are required.' });
    }

    // Validate email format
    if (!validator.isEmail(email)) {
        return res.status(400).json({ message: 'Invalid email format.' });
    }

    try {
        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        // SQL query to insert the user into the database
        const query = `
            INSERT INTO users (username, email, password, first_name, last_name, phone)
            VALUES (?, ?, ?, ?, ?, ?)
        `;

        db.query(query, [username, email, hashedPassword, first_name, last_name, phone], (err) => {
            if (err) {
                if (err.code === 'ER_DUP_ENTRY') {
                    return res.status(409).json({
                        error: {
                            message: 'Username or email already exists.',
                            code: 'DUPLICATE_USERNAME_OR_EMAIL',
                            details: `The username or email "${username}" is already in use.`,
                        },
                    });
                }

                return res.status(500).json({
                    error: {
                        message: 'Error registering user.',
                        code: 'SERVER_ERROR',
                        details: err.message || 'Unknown error occurred while registering user.',
                    },
                });
            }

            // Respond with success
            res.status(201).json({ message: 'User registered successfully.' });
        });
    } catch (error) {
        res.status(500).json({ message: 'Server error.', error });
    }
});

// Login
router.post('/login', (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ message: 'Username and password are required.' });
    }

    const query = 'SELECT * FROM users WHERE username = ?';
    db.query(query, [username], async (err, results) => {
        if (err) {
            return res.status(500).json({ message: 'Error logging in.', error: err });
        }

        if (results.length === 0) {
            return res.status(401).json({ message: 'Invalid credentials.' });
        }

        const user = results[0];
        const isPasswordValid = await bcrypt.compare(password, user.password);

        if (!isPasswordValid) {
            return res.status(401).json({ message: 'Invalid credentials.' });
        }

        const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.json({ message: 'Login successful.', token });
    });
});

// Protected route example
router.get('/profile', (req, res) => {
    const token = req.headers['authorization'];

    if (!token) {
        return res.status(401).json({ message: 'No token provided.' });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(401).json({ message: 'Invalid token.' });
        }

        res.json({ message: 'Protected data.', userId: decoded.id });
    });
});

// Update password
router.post('/update-password', async (req, res) => {
    const { username, oldPassword, newPassword } = req.body;
    const token = req.headers['authorization'];

    if (!token) {
        return res.status(401).json({ message: 'No token provided.' });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(401).json({ message: 'Invalid token.' });
        }

        if (oldPassword === newPassword) {
            return res.status(400).json({ message: 'Old password must not be the same as the new password.' });
        }

        if (!username || !oldPassword || !newPassword) {
            return res.status(400).json({ message: 'Username, old password, and new password are required.' });
        }

        const query = 'SELECT * FROM users WHERE username = ?';
        db.query(query, [username], async (err, results) => {
            if (err) {
                return res.status(500).json({ message: 'Error checking user existence.', error: err });
            }

            if (results.length === 0) {
                return res.status(404).json({ message: 'User not found.' });
            }

            const user = results[0];
            const isPasswordValid = await bcrypt.compare(oldPassword, user.password);
            if (!isPasswordValid) {
                return res.status(401).json({ message: 'Incorrect old password.' });
            }

            const hashedNewPassword = await bcrypt.hash(newPassword, 10);
            const updateQuery = 'UPDATE users SET password = ? WHERE username = ?';
            db.query(updateQuery, [hashedNewPassword, username], (err) => {
                if (err) {
                    return res.status(500).json({ message: 'Error updating password.', error: err });
                }

                return res.status(200).json({ message: 'Password updated successfully.' });
            });
        });
    });
});

module.exports = router;
