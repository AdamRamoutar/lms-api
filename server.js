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

// A subject's outline: its details, then each module with its topics. Titles are public, like the other browsing routes.
app.get('/subjects/:id/outline', async (req, res) => {
    const subjectId = Number(req.params.id);

    if (!Number.isInteger(subjectId) || subjectId < 1) {
        return res.status(400).json({ error: 'Invalid subject id.' });
    }

    try {
        const subjectResult = await pool.query(
            `SELECT s.id, s.name, s.description, s.unit, l.id AS level_id, l.name AS level_name
             FROM subjects AS s
             JOIN levels AS l ON l.id = s.level_id
             WHERE s.id = $1`,
            [subjectId]
        );

        if (subjectResult.rowCount === 0) {
            return res.status(404).json({ error: 'Subject not found.' });
        }

        // The two lists don't depend on each other, so they run together.
        const [modulesResult, topicsResult] = await Promise.all([
            pool.query(
                'SELECT id, title, position FROM modules WHERE subject_id = $1 ORDER BY position',
                [subjectId]
            ),
            pool.query(
                `SELECT t.id, t.module_id, t.title, t.position, COUNT(st.id)::int AS lesson_count
                 FROM topics AS t
                 JOIN modules AS m ON m.id = t.module_id
                 LEFT JOIN subtopics AS st ON st.topic_id = t.id
                 WHERE m.subject_id = $1
                 GROUP BY t.id
                 ORDER BY t.position`,
                [subjectId]
            )
        ]);

        const modules = modulesResult.rows.map((moduleRow) => ({
            ...moduleRow,
            topics: topicsResult.rows.filter((topicRow) => topicRow.module_id === moduleRow.id)
        }));

        res.json({ ...subjectResult.rows[0], modules });
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

// A lesson's public details: its title, where it sits in the syllabus, and which sections it has.
// It never includes the video link or the notes, so a visitor can see what a locked lesson is without being able to read it.
app.get('/subtopics/:id/context', async (req, res) => {
    const lessonId = Number(req.params.id);

    if (!Number.isInteger(lessonId) || lessonId < 1) {
        return res.status(400).json({ error: 'Invalid lesson id.' });
    }

    try {
        const result = await pool.query(
            `SELECT st.id,
                    st.title,
                    st.is_free,
                    (st.video_link IS NOT NULL) AS has_video,
                    (st.note_content IS NOT NULL) AS has_notes,
                    t.id AS topic_id,
                    t.title AS topic_title,
                    s.id AS subject_id,
                    s.name AS subject_name,
                    l.name AS level_name
             FROM subtopics AS st
             JOIN topics AS t ON t.id = st.topic_id
             JOIN modules AS m ON m.id = t.module_id
             JOIN subjects AS s ON s.id = m.subject_id
             JOIN levels AS l ON l.id = s.level_id
             WHERE st.id = $1`,
            [lessonId]
        );

        if (result.rowCount === 0) {
            return res.status(404).json({ error: 'Lesson not found.' });
        }

        res.json(result.rows[0]);
    }
    catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

//get content
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

// Marks a lesson complete for the logged-in student. Safe to repeat: a second request changes nothing.
// The student comes from the token and never from the request, so nobody can mark progress for someone else.
app.put('/subtopics/:id/progress', authenticateToken, async (req, res) => {
    const lessonId = Number(req.params.id);

    if (!Number.isInteger(lessonId) || lessonId < 1) {
        return res.status(400).json({ error: 'Invalid lesson id.' });
    }

    try {
        await pool.query(
            `INSERT INTO lesson_progress (user_id, subtopic_id)
             VALUES ($1, $2)
             ON CONFLICT (user_id, subtopic_id) DO NOTHING`,
            [req.user.userId, lessonId]
        );

        res.json({ message: 'Lesson marked as complete.' });
    }
    catch (err) {
        // 23503 is a foreign key violation. Which key failed says whether the lesson or the account is missing.
        if (err.code === '23503' && err.constraint === 'lesson_progress_subtopic_id_fkey') {
            return res.status(404).json({ error: 'Lesson not found.' });
        }

        // The token still verifies for up to an hour after an account is deleted, so to the page this is an invalid login.
        if (err.code === '23503' && err.constraint === 'lesson_progress_user_id_fkey') {
            return rejectToken(res, 'INVALID_TOKEN');
        }

        console.error(err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Marks a lesson incomplete again. Safe to repeat: deleting a row that isn't there is not an error.
app.delete('/subtopics/:id/progress', authenticateToken, async (req, res) => {
    const lessonId = Number(req.params.id);

    if (!Number.isInteger(lessonId) || lessonId < 1) {
        return res.status(400).json({ error: 'Invalid lesson id.' });
    }

    try {
        await pool.query(
            `DELETE FROM lesson_progress
             WHERE user_id = $1 AND subtopic_id = $2`,
            [req.user.userId, lessonId]
        );

        res.json({ message: 'Lesson marked as incomplete.' });
    }
    catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

//auth
// Why a token was refused. The code is what a page reacts to, and the message is a fallback it can show.
// The wording is general, because the same codes are used by the lesson route and the progress routes.
const AUTH_MESSAGES = {
    NO_TOKEN: 'Please log in to continue.',
    TOKEN_EXPIRED: 'Your session has expired. Please log in again.',
    INVALID_TOKEN: 'Your login is not valid. Please log in again.'
};

// Every refusal has the same shape, whichever route produces it.
function rejectToken(res, code) {
    return res.status(401).json({ error: AUTH_MESSAGES[code], code });
}

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
        return rejectToken(res, 'NO_TOKEN');
    }

    const token = authHeader.split(' ')[1];

    try {
        req.user = jwt.verify(token, process.env.JWT_SECRET, { algorithms: ['HS256'] });
    }
    catch (err) {
        return rejectToken(res, err.name === 'TokenExpiredError' ? 'TOKEN_EXPIRED' : 'INVALID_TOKEN');
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

