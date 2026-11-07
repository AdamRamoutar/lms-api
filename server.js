require('dotenv').config();
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const express = require('express');
const app = express();
app.use(express.json());
app.use(cors({ origin: process.env.FRONTEND_URL || 'http://127.0.0.1:5500' }));

const port = process.env.PORT || 3000;

const pool = new Pool(

    process.env.DATABASE_URL
        ?
        {
            connectionString: process.env.DATABASE_URL,
        }
        :
        {
            user: process.env.DB_USER,
            host: process.env.DB_HOST,
            database: process.env.DB_NAME,
            password: process.env.DB_PASSWORD,
            port: process.env.DB_PORT,
            max: 20, //overide default max connections
            idleTimeoutMillis: 30000, //close idle clients after 30 seconds
            connectionTimeoutMillis: 2000, //return an error after 2 seconds if connection fails
        }
);

//get levels
app.get('/levels', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM levels ORDER BY id ASC');
        res.json(result.rows);

    }
    catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.get('/levels/:id', async (req, res) => {
    const targetID = Number(req.params.id);

    if (!Number.isInteger(targetID) || targetID < 1) {
        return res.status(400).json({ error: 'Invalid level id.' });
    }

    try {
        const result = await pool.query(
            'SELECT id, name FROM levels WHERE id = $1',
            [targetID]
        );

        if (result.rowCount === 0) {
            return res.status(404).json({ error: 'Level not found.' });
        }

        res.json(result.rows[0]);
    }
    catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

//get subjects
app.get('/levels/:id/subjects', async (req, res) => {
    const targetID = Number((req.params.id));
    let result;

    try {
        if (req.query.unit) {
            const unitNumber = Number((req.query.unit));
            result = await pool.query(
                'SELECT * FROM subjects WHERE level_id = $1 AND unit = $2 ORDER BY id ASC',
                [targetID, unitNumber]
            );
        }
        else {
            result = await pool.query(
                'SELECT * FROM subjects WHERE level_id = $1 ORDER BY id ASC',
                [targetID]
            );
        }

        res.json(result.rows);
    }
    catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

//get topics
app.get('/subjects/:id/topics', async (req, res) => {
    const targetID = Number((req.params.id));

    try{
        const result = await pool.query(
            'SELECT * FROM topics WHERE subject_id = $1 ORDER BY position ASC',
            [targetID]
        );

        res.json(result.rows);
    }
    catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

//get subtopics
app.get('/topics/:id/subtopics', async (req, res) => {
    const targetID = Number((req.params.id));

    try {
        const result = await pool.query(
            'SELECT id, title, is_free FROM subtopics WHERE topic_id = $1 ORDER BY position',
            [targetID]
        );
        res.json(result.rows);
    }
    catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

//get content
const AUTH_MESSAGES = {
    NO_TOKEN: 'Please log in to view this lesson.',
    TOKEN_EXPIRED: 'Your session has expired. Please log in again.',
    INVALID_TOKEN: 'Your login is not valid. Please log in again.'
};

app.get('/subtopics/:id', optionalAuth, async (req, res) => {
    const targetID = Number(req.params.id);

    try {
        const result = await pool.query(
            'SELECT title, video_link, note_content, is_free FROM subtopics WHERE id = $1',
            [targetID]
        );

        if (result.rowCount === 0) {
            return res.status(404).json({ error: 'Lesson not found.' });
        }

        const lesson = result.rows[0];

        if (!lesson.is_free && !req.user) {
            return res.status(401).json({
                error: AUTH_MESSAGES[req.authError],
                code: req.authError
            });
        }

        res.json(lesson);
    }
    catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/register', async (req, res) => {
    const { email, password } = req.body ?? {};

    if (!email || !password || typeof email !== 'string' || typeof password !== 'string') {
        return res.status(400).json({ error: 'Email and password are required.' });
    }

    if (password.length < 8) {
        return res.status(400).json({ error: 'Password must be at least 8 characters.' });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);

        await pool.query(
            'INSERT INTO users (email, password) VALUES ($1, $2)',
            [email, hashedPassword]
        );

        res.status(201).json({ message: 'User created successfully.' });
    }
    catch (err) {
        if (err.code === '23505') {
            return res.status(409).json({ error: 'Email already exists.' });
        }
        console.error(err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/login', async (req, res) => {
    const { email, password } = req.body ?? {};

    if (!email || !password || typeof email !== 'string' || typeof password !== 'string') {
        return res.status(400).json({ error: 'Email and password are required.' });
    }

    try {
        const result = await pool.query(
            'SELECT id, email, password FROM users WHERE email = $1',
            [email]
        );
        const user = result.rows[0];

        if (!user) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        const token = jwt.sign(
            { userId: user.id, email: user.email },
            process.env.JWT_SECRET,
            { expiresIn: '1h' }
        );

        res.status(200).json({ message: 'Login successful', token });
    }
    catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

function authenticateToken(req, res, next) {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Access denied, no token provided' });
    }

    const token = authHeader.split(' ')[1];

    try {
        req.user = jwt.verify(token, process.env.JWT_SECRET, { algorithms: ['HS256'] });
    }
    catch (err) {
        if (err.name === 'TokenExpiredError') {
            return res.status(401).json({ error: 'Token has expired.' });
        }
        return res.status(401).json({ error: 'Invalid token.' });
    }

    next();
}

// Reads the login token if there is one, but never blocks the request.
// Routes decide for themselves what a missing or bad token means.
function optionalAuth(req, res, next) {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        req.authError = 'NO_TOKEN';
        return next();
    }

    const token = authHeader.split(' ')[1];

    try {
        req.user = jwt.verify(token, process.env.JWT_SECRET, { algorithms: ['HS256'] });
    }
    catch (err) {
        req.authError = err?.name === 'TokenExpiredError' ? 'TOKEN_EXPIRED' : 'INVALID_TOKEN';
    }

    next();
}

app.listen(port, () => {
    console.log("The server is running");
});

