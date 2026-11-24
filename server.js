require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');

// ---------- Settings ----------

const PORT = process.env.PORT || 3000;
const PASSWORD_MIN_LENGTH = 8;
const BCRYPT_ROUNDS = 10;
const TOKEN_LIFETIME = '1h';

// ---------- Setup ----------

const app = express();
app.use(express.json());
app.use(cors({ origin: process.env.FRONTEND_URL || 'http://127.0.0.1:5500' }));

// On Render the whole connection comes from DATABASE_URL. Locally, the separate DB_ values are used.
// The timeouts are only set for local use: a hosted database can take a moment to wake up,
// and a short connection timeout would make the first request fail.
const pool = new Pool(
    process.env.DATABASE_URL
        ? { connectionString: process.env.DATABASE_URL }
        : {
            user: process.env.DB_USER,
            host: process.env.DB_HOST,
            database: process.env.DB_NAME,
            password: process.env.DB_PASSWORD,
            port: process.env.DB_PORT,
            max: 20,
            idleTimeoutMillis: 30000,
            connectionTimeoutMillis: 2000
        }
);

// ---------- Helpers ----------

// Turns a value from the address into a whole number of at least 1, or null if it isn't one.
function parsePositiveInt(value) {
    const number = Number(value);

    return Number.isInteger(number) && number >= 1 ? number : null;
}

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

// Reads the login token from a request. Returns the logged-in student, or the code that says why there isn't one.
function readToken(req) {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return { error: 'NO_TOKEN' };
    }

    try {
        const user = jwt.verify(authHeader.split(' ')[1], process.env.JWT_SECRET, { algorithms: ['HS256'] });
        return { user };
    }
    catch (err) {
        return { error: err.name === 'TokenExpiredError' ? 'TOKEN_EXPIRED' : 'INVALID_TOKEN' };
    }
}

// Blocks the request unless the student is logged in.
function authenticateToken(req, res, next) {
    const { user, error } = readToken(req);

    if (error) {
        return rejectToken(res, error);
    }

    req.user = user;
    next();
}

// Reads the login token if there is one, but never blocks the request.
// Routes decide for themselves what a missing or bad token means.
function optionalAuth(req, res, next) {
    const { user, error } = readToken(req);

    if (user) {
        req.user = user;
    }
    else {
        req.authError = error;
    }

    next();
}

// Looks up a student's current account in the database. The token only says who they are, and it stays valid
// for an hour, so a role kept in it could be out of date. Returns null if the account no longer exists.
async function loadCurrentUser(userId) {
    const result = await pool.query('SELECT id, email, role FROM users WHERE id = $1', [userId]);

    return result.rows[0] ?? null;
}

// Lets only admins through. It must come after authenticateToken, because it needs req.user.
async function requireAdmin(req, res, next) {
    try {
        const user = await loadCurrentUser(req.user.userId);

        // The token still verifies for up to an hour after an account is deleted, so to the page this is an invalid login.
        if (!user) {
            return rejectToken(res, 'INVALID_TOKEN');
        }

        // 403 means "I know who you are, and you may not do this". 401 would mean "I don't know who you are".
        if (user.role !== 'admin') {
            return res.status(403).json({ error: 'You do not have access to this.', code: 'FORBIDDEN' });
        }

        req.currentUser = user;
        next();
    }
    catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Internal server error' });
    }
}

// ---------- Browsing: levels, subjects, topics, lessons ----------
// Titles are public. Only a lesson's content is protected.

app.get('/levels', async (req, res) => {
    try {
        const result = await pool.query('SELECT id, name FROM levels ORDER BY id');
        res.json(result.rows);
    }
    catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.get('/levels/:id', async (req, res) => {
    const levelId = parsePositiveInt(req.params.id);

    if (levelId === null) {
        return res.status(400).json({ error: 'Invalid level id.' });
    }

    try {
        const result = await pool.query('SELECT id, name FROM levels WHERE id = $1', [levelId]);

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

// The subjects of a level, optionally only one CAPE unit. A level with no subjects returns an empty list.
app.get('/levels/:id/subjects', async (req, res) => {
    const levelId = parsePositiveInt(req.params.id);
    const unit = req.query.unit === undefined ? null : Number(req.query.unit);

    if (levelId === null) {
        return res.status(400).json({ error: 'Invalid level id.' });
    }

    if (unit !== null && ![1, 2].includes(unit)) {
        return res.status(400).json({ error: 'Invalid unit.' });
    }

    try {
        // A null unit means "any unit", so the same query serves both cases.
        const result = await pool.query(
            `SELECT id, name, level_id, unit, description
             FROM subjects
             WHERE level_id = $1 AND ($2::int IS NULL OR unit = $2)
             ORDER BY id`,
            [levelId, unit]
        );

        res.json(result.rows);
    }
    catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// A subject's outline: its details, then each module with its topics.
app.get('/subjects/:id/outline', async (req, res) => {
    const subjectId = parsePositiveInt(req.params.id);

    if (subjectId === null) {
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
                 LEFT JOIN subtopics AS st ON st.topic_id = t.id AND st.is_published
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

// The lessons in a topic. A topic with no lessons returns an empty list.
app.get('/topics/:id/subtopics', async (req, res) => {
    const topicId = parsePositiveInt(req.params.id);

    if (topicId === null) {
        return res.status(400).json({ error: 'Invalid topic id.' });
    }

    try {
        const result = await pool.query(
            'SELECT id, title, is_free FROM subtopics WHERE topic_id = $1 AND is_published ORDER BY position',
            [topicId]
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
    const lessonId = parsePositiveInt(req.params.id);

    if (lessonId === null) {
        return res.status(400).json({ error: 'Invalid lesson id.' });
    }

    try {
        const result = await pool.query(
            `SELECT st.id,
                    st.title,
                    st.is_free,
                    EXISTS (SELECT 1 FROM lesson_videos AS lv WHERE lv.subtopic_id = st.id) AS has_video,
                    (SELECT COUNT(*)::int FROM lesson_videos AS lv WHERE lv.subtopic_id = st.id) AS video_count,
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
             WHERE st.id = $1 AND st.is_published`,
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

// A lesson's content. Free lessons are open to everyone, and the rest need a logged-in student.
app.get('/subtopics/:id', optionalAuth, async (req, res) => {
    const lessonId = parsePositiveInt(req.params.id);

    if (lessonId === null) {
        return res.status(400).json({ error: 'Invalid lesson id.' });
    }

    try {
        const result = await pool.query(
            'SELECT title, note_content, is_free FROM subtopics WHERE id = $1 AND is_published',
            [lessonId]
        );

        if (result.rowCount === 0) {
            return res.status(404).json({ error: 'Lesson not found.' });
        }

        const lesson = result.rows[0];

        if (!lesson.is_free && !req.user) {
            return rejectToken(res, req.authError);
        }

        // Only after the access check, so a locked lesson's videos are never even read for a visitor.
        const videosResult = await pool.query(
            'SELECT id, title, video_link, position FROM lesson_videos WHERE subtopic_id = $1 ORDER BY position',
            [lessonId]
        );

        res.json({ ...lesson, videos: videosResult.rows });
    }
    catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// ---------- Progress (logged-in students only) ----------

// Marks a lesson complete for the logged-in student. Safe to repeat: a second request changes nothing.
// The student comes from the token and never from the request, so nobody can mark progress for someone else.
app.put('/subtopics/:id/progress', authenticateToken, async (req, res) => {
    const lessonId = parsePositiveInt(req.params.id);

    if (lessonId === null) {
        return res.status(400).json({ error: 'Invalid lesson id.' });
    }

    try {
        // A draft isn't visible to students, so it can't be completed either.
        const lesson = await pool.query('SELECT 1 FROM subtopics WHERE id = $1 AND is_published', [lessonId]);

        if (lesson.rowCount === 0) {
            return res.status(404).json({ error: 'Lesson not found.' });
        }

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
    const lessonId = parsePositiveInt(req.params.id);

    if (lessonId === null) {
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

// The logged-in student's completed lessons in one subject, each with its topic, so a page can count them per topic.
// A subject with no progress, or one that doesn't exist, returns an empty list: the answer is "nothing completed".
app.get('/subjects/:id/progress', authenticateToken, async (req, res) => {
    const subjectId = parsePositiveInt(req.params.id);

    if (subjectId === null) {
        return res.status(400).json({ error: 'Invalid subject id.' });
    }

    try {
        const result = await pool.query(
            `SELECT lp.subtopic_id, st.topic_id
             FROM lesson_progress AS lp
             JOIN subtopics AS st ON st.id = lp.subtopic_id
             JOIN topics AS t ON t.id = st.topic_id
             JOIN modules AS m ON m.id = t.module_id
             WHERE lp.user_id = $1 AND m.subject_id = $2 AND st.is_published
             ORDER BY lp.subtopic_id`,
            [req.user.userId, subjectId]
        );

        res.json(result.rows);
    }
    catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// ---------- Admin (admins only) ----------

// One gate for everything under /admin, so a route added later can't forget it.
// It must stay above every admin route, because Express runs things from the top down.
app.use('/admin', authenticateToken, requireAdmin);

// The lessons in a topic, drafts included, with what an admin needs to see at a glance.
app.get('/admin/topics/:id/lessons', async (req, res) => {
    const topicId = parsePositiveInt(req.params.id);

    if (topicId === null) {
        return res.status(400).json({ error: 'Invalid topic id.' });
    }

    try {
        const topicResult = await pool.query('SELECT 1 FROM topics WHERE id = $1', [topicId]);

        if (topicResult.rowCount === 0) {
            return res.status(404).json({ error: 'Topic not found.' });
        }

        // "Has notes" means real text, so a blank note counts as no note.
        const result = await pool.query(
            `SELECT st.id, st.title, st.position, st.is_free, st.is_published, st.updated_at,
                    (COALESCE(btrim(st.note_content), '') <> '') AS has_notes,
                    (SELECT COUNT(*)::int FROM lesson_videos AS lv WHERE lv.subtopic_id = st.id) AS video_count
             FROM subtopics AS st
             WHERE st.topic_id = $1
             ORDER BY st.position`,
            [topicId]
        );

        res.json(result.rows);
    }
    catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// One lesson in full, for the editor: its content, its place in the syllabus, and its videos. Drafts are included.
app.get('/admin/lessons/:id', async (req, res) => {
    const lessonId = parsePositiveInt(req.params.id);

    if (lessonId === null) {
        return res.status(400).json({ error: 'Invalid lesson id.' });
    }

    try {
        const lessonResult = await pool.query(
            `SELECT st.id, st.title, st.note_content, st.position, st.is_free, st.is_published, st.updated_at,
                    t.id AS topic_id, t.title AS topic_title,
                    s.id AS subject_id, s.name AS subject_name
             FROM subtopics AS st
             JOIN topics AS t ON t.id = st.topic_id
             JOIN modules AS m ON m.id = t.module_id
             JOIN subjects AS s ON s.id = m.subject_id
             WHERE st.id = $1`,
            [lessonId]
        );

        if (lessonResult.rowCount === 0) {
            return res.status(404).json({ error: 'Lesson not found.' });
        }

        const videosResult = await pool.query(
            'SELECT id, title, video_link, position FROM lesson_videos WHERE subtopic_id = $1 ORDER BY position',
            [lessonId]
        );

        res.json({ ...lessonResult.rows[0], videos: videosResult.rows });
    }
    catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// ---------- Accounts ----------

app.post('/register', async (req, res) => {
    const { email, password } = req.body ?? {};

    if (!email || !password || typeof email !== 'string' || typeof password !== 'string') {
        return res.status(400).json({ error: 'Email and password are required.' });
    }

    if (password.length < PASSWORD_MIN_LENGTH) {
        return res.status(400).json({ error: `Password must be at least ${PASSWORD_MIN_LENGTH} characters.` });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, BCRYPT_ROUNDS);

        await pool.query(
            'INSERT INTO users (email, password) VALUES ($1, $2)',
            [email, hashedPassword]
        );

        res.status(201).json({ message: 'User created successfully.' });
    }
    catch (err) {
        // 23505 is a unique violation: the email is already registered.
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

        // The same answer for an unknown email and a wrong password, so a visitor can't tell which accounts exist.
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        const token = jwt.sign(
            { userId: user.id, email: user.email },
            process.env.JWT_SECRET,
            { expiresIn: TOKEN_LIFETIME }
        );

        res.status(200).json({ message: 'Login successful', token });
    }
    catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Who the logged-in student is. The page uses it to decide whether to show the Admin link,
// but the real protection is requireAdmin, which runs on the server for every admin route.
app.get('/me', authenticateToken, async (req, res) => {
    try {
        const user = await loadCurrentUser(req.user.userId);

        if (!user) {
            return rejectToken(res, 'INVALID_TOKEN');
        }

        res.json({ email: user.email, role: user.role });
    }
    catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// ---------- Errors outside any route ----------

// A request body that isn't valid JSON is the sender's mistake, so it gets a plain 400 and no stack trace.
// This must come after every route.
app.use((err, req, res, next) => {
    if (err.type === 'entity.parse.failed') {
        return res.status(400).json({ error: 'Invalid JSON.' });
    }

    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
});

app.listen(PORT, () => {
    console.log(`The server is running on port ${PORT}`);
});

