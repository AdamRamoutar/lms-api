require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const { parse } = require('dotenv');

// ---------- Settings ----------

const PORT = process.env.PORT || 3000;
const PASSWORD_MIN_LENGTH = 8;
const BCRYPT_ROUNDS = 10;
const TOKEN_LIFETIME = '1h';
const TITLE_MAX_LENGTH = 255;
const VIDEO_LINK_MAX_LENGTH = 2048;

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

// The body of an admin request, or an empty object if it isn't a plain object.
function readBody(req) {
    const body = req.body;

    return body !== null && typeof body === 'object' && !Array.isArray(body) ? body : {};
}

// A title from an admin form: real text, no longer than the column allows. Returns the cleaned title, or null if it isn't valid.
function cleanTitle(value) {
    if (typeof value !== 'string') {
        return null;
    }

    const title = value.trim();

    return title !== '' && title.length <= TITLE_MAX_LENGTH ? title : null;
}

// Notes may be empty. Blank notes are stored as null, so "has notes" never has to wonder about empty text.
// Returns { ok: true, value } or { ok: false } when the value isn't text or null.
function cleanNotes(value) {
    if (value === null) {
        return { ok: true, value: null };
    }

    if (typeof value !== 'string') {
        return { ok: false };
    }

    return { ok: true, value: value.trim() === '' ? null : value };
}

// What stops a lesson from being published. An empty list means it's ready.
// This is the one definition of the rules: the publish route enforces it, the edit route protects live lessons with it,
// and the editor's checklist shows it.
function findPublishProblems({ title, note_content, video_count }) {
    const problems = [];

    if (typeof title !== 'string' || title.trim() === '') {
        problems.push({ code: 'MISSING_TITLE', message: 'Add a title.' });
    }

    const hasNotes = typeof note_content === 'string' && note_content.trim() !== '';

    if (!hasNotes && video_count === 0) {
        problems.push({ code: 'MISSING_CONTENT', message: 'Add notes or at least one video.' });
    }

    return problems;
}

// A refusal that carries its own answer, so work inside a transaction can stop and roll back cleanly.
class Refusal extends Error {
    constructor(status, body) {
        super(body.error);
        this.status = status;
        this.body = body;
    }
}

// Sends the right answer for a failed admin request: a planned refusal keeps its own answer, anything else is a 500.
function handleAdminError(res, err) {
    if (err instanceof Refusal) {
        return res.status(err.status).json(err.body);
    }

    // 23514 is a check violation: the database refused a link that isn't a web address.
    if (err.code === '23514') {
        return res.status(400).json({ error: 'A video link must be a web address starting with http:// or https://.' });
    }

    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
}

// Runs several changes as one unit: they all happen, or none do. The work gets its own connection to use.
async function withTransaction(work) {
    const client = await pool.connect();

    try {
        await client.query('BEGIN');
        const result = await work(client);
        await client.query('COMMIT');
        return result;
    }
    catch (err) {
        await client.query('ROLLBACK');
        throw err;
    }
    finally {
        client.release();
    }
}

// Locks a lesson's row until the transaction ends, so two requests changing its videos take turns.
// Returns what the rules need to know about the lesson, or stops the request if there is no such lesson.
async function lockLesson(client, lessonId) {
    const result = await client.query(
        'SELECT title, note_content, is_published FROM subtopics WHERE id = $1 FOR UPDATE',
        [lessonId]
    );

    if (result.rowCount === 0) {
        throw new Refusal(404, { error: 'Lesson not found.' });
    }

    return result.rows[0];
}

// A video link from an admin form: a web address, not too long. Returns the cleaned link, or null if it isn't valid.
function cleanVideoLink(value) {
    if (typeof value !== 'string') {
        return null;
    }

    const link = value.trim();

    if (link === '' || link.length > VIDEO_LINK_MAX_LENGTH || !/^https?:\/\//i.test(link)) {
        return null;
    }

    try {
        const { protocol } = new URL(link);
        return protocol === 'https:' || protocol === 'http:' ? link : null;
    }
    catch {
        return null;
    }
}

// A video's title is optional. A blank title is stored as null, and the page then shows "Video 1", "Video 2".
// Returns { ok: true, value } or { ok: false } when the value isn't text or null, or is too long.
function cleanVideoTitle(value) {
    if (value === null) {
        return { ok: true, value: null };
    }

    if (typeof value !== 'string') {
        return { ok: false };
    }

    const title = value.trim();

    if (title.length > TITLE_MAX_LENGTH) {
        return { ok: false };
    }

    return { ok: true, value: title === '' ? null : title };
}

// A lesson's videos in order, for the answers that send the whole list back.
async function loadVideos(client, lessonId) {
    const result = await client.query(
        'SELECT id, title, video_link, position FROM lesson_videos WHERE subtopic_id = $1 ORDER BY position',
        [lessonId]
    );

    return result.rows;
}

// The tables whose rows have an order within a parent. Table and column names can't be sent as values in a query,
// so they come from this fixed list and never from a request.
const ORDERED_TABLES = {
    modules: { parentTable: 'subjects', parentColumn: 'subject_id' },
    topics: { parentTable: 'modules', parentColumn: 'module_id' },
    subtopics: { parentTable: 'topics', parentColumn: 'topic_id' }
};

// Moves a row one place up or down among the rows with the same parent. Returns the parent's id.
async function moveWithinParent(client, table, id, direction) {
    const config = ORDERED_TABLES[table];

    if (!config) {
        throw new Error(`Not an ordered table: ${table}`);
    }

    const { parentTable, parentColumn } = config;

    // Locking the parent makes everyone moving its children take turns.
    await client.query(
        `SELECT 1 FROM ${parentTable} WHERE id = (SELECT ${parentColumn} FROM ${table} WHERE id = $1) FOR UPDATE`,
        [id]
    );

    // Read after the lock, so the position is never out of date.
    const found = await client.query(`SELECT ${parentColumn} AS parent_id, position FROM ${table} WHERE id = $1`, [id]);

    if (found.rowCount === 0) {
        throw new Refusal(404, { error: 'Not found.' });
    }

    const { parent_id: parentId, position } = found.rows[0];

    // The neighbour is the next row in that direction, so gaps left by deleted rows don't matter.
    const neighbour = await client.query(
        direction === 'up'
            ? `SELECT id, position FROM ${table} WHERE ${parentColumn} = $1 AND position < $2 ORDER BY position DESC LIMIT 1`
            : `SELECT id, position FROM ${table} WHERE ${parentColumn} = $1 AND position > $2 ORDER BY position ASC LIMIT 1`,
        [parentId, position]
    );

    // Already first or last: nothing to move.
    if (neighbour.rowCount === 0) {
        return parentId;
    }

    const other = neighbour.rows[0];

    // Two rows can't share a place, so the swap goes in three moves, via a temporary place.
    await client.query(`UPDATE ${table} SET position = -1 WHERE id = $1`, [id]);
    await client.query(`UPDATE ${table} SET position = $2 WHERE id = $1`, [other.id, position]);
    await client.query(`UPDATE ${table} SET position = $2 WHERE id = $1`, [id, other.position]);

    return parentId;
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

        const lesson = lessonResult.rows[0];
        const videos = videosResult.rows;

        res.json({
            ...lesson,
            videos,
            publish_problems: findPublishProblems({ ...lesson, video_count: videos.length })
        });
    }
    catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Creates a new lesson at the end of a topic. It starts as an empty draft, so students can't see it.
app.post('/admin/topics/:id/lessons', async (req, res) => {
    const topicId = parsePositiveInt(req.params.id);

    if (topicId === null) {
        return res.status(400).json({ error: 'Invalid topic id.' });
    }

    const title = cleanTitle(readBody(req).title);

    if (title === null) {
        return res.status(400).json({ error: `A title is required, up to ${TITLE_MAX_LENGTH} characters.` });
    }

    try {
        // The position is worked out in the same statement as the insert: one more than the highest in this topic.
        const result = await pool.query(
            `INSERT INTO subtopics (title, position, topic_id)
             VALUES ($1, (SELECT COALESCE(MAX(position), 0) + 1 FROM subtopics WHERE topic_id = $2), $2)
             RETURNING id, title, position, is_free, is_published, updated_at`,
            [title, topicId]
        );

        res.status(201).json(result.rows[0]);
    }
    catch (err) {
        // 23503 is a foreign key violation: the topic doesn't exist.
        if (err.code === '23503') {
            return res.status(404).json({ error: 'Topic not found.' });
        }

        // 23505 is a unique violation: another lesson took the same position at the same moment.
        if (err.code === '23505') {
            return res.status(409).json({ error: 'Another lesson was added at the same moment. Please try again.' });
        }

        console.error(err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Changes a lesson's title, notes or free setting. Only the fields sent are changed.
// It never changes is_published or the order: publishing has its own rules, and ordering has its own route.
app.patch('/admin/lessons/:id', async (req, res) => {
    const lessonId = parsePositiveInt(req.params.id);

    if (lessonId === null) {
        return res.status(400).json({ error: 'Invalid lesson id.' });
    }

    const body = readBody(req);
    const hasTitle = 'title' in body;
    const hasNotes = 'note_content' in body;
    const hasFree = 'is_free' in body;

    if (!hasTitle && !hasNotes && !hasFree) {
        return res.status(400).json({ error: 'Send at least one of: title, note_content, is_free.' });
    }

    try {
        const currentResult = await pool.query(
            `SELECT title, note_content, is_free, is_published,
                    (SELECT COUNT(*)::int FROM lesson_videos AS lv WHERE lv.subtopic_id = subtopics.id) AS video_count
             FROM subtopics
             WHERE id = $1`,
            [lessonId]
        );

        if (currentResult.rowCount === 0) {
            return res.status(404).json({ error: 'Lesson not found.' });
        }

        const current = currentResult.rows[0];
        let title = current.title;
        let notes = current.note_content;
        let isFree = current.is_free;

        if (hasTitle) {
            const cleaned = cleanTitle(body.title);

            if (cleaned === null) {
                return res.status(400).json({ error: `A title is required, up to ${TITLE_MAX_LENGTH} characters.` });
            }

            title = cleaned;
        }

        if (hasNotes) {
            const cleaned = cleanNotes(body.note_content);

            if (!cleaned.ok) {
                return res.status(400).json({ error: 'Notes must be text, or null to clear them.' });
            }

            notes = cleaned.value;
        }

        if (hasFree) {
            if (typeof body.is_free !== 'boolean') {
                return res.status(400).json({ error: 'is_free must be true or false.' });
            }

            isFree = body.is_free;
        }

        // A live lesson must keep meeting the publishing rules, at every save.
        if (current.is_published && findPublishProblems({ title, note_content: notes, video_count: current.video_count }).length > 0) {
            return res.status(409).json({
                error: 'A live lesson needs notes or at least one video. Add one, or unpublish the lesson first.',
                code: 'LESSON_WOULD_BE_EMPTY'
            });
        }

        const result = await pool.query(
            `UPDATE subtopics
             SET title = $1, note_content = $2, is_free = $3, updated_at = NOW()
             WHERE id = $4
             RETURNING id, title, note_content, position, is_free, is_published, updated_at`,
            [title, notes, isFree, lessonId]
        );

        res.json(result.rows[0]);
    }
    catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Makes a lesson visible to students, but only if it meets the publishing rules.
// The check and the change happen in one statement, so nothing can slip in between them.
app.post('/admin/lessons/:id/publish', async (req, res) => {
    const lessonId = parsePositiveInt(req.params.id);

    if (lessonId === null) {
        return res.status(400).json({ error: 'Invalid lesson id.' });
    }

    try {
        // Publishing a lesson that is already published changes nothing, including its "last edited" time.
        const result = await pool.query(
            `UPDATE subtopics
             SET is_published = TRUE,
                 updated_at = CASE WHEN is_published THEN updated_at ELSE NOW() END
             WHERE id = $1
               AND btrim(title) <> ''
               AND (COALESCE(btrim(note_content), '') <> ''
                    OR EXISTS (SELECT 1 FROM lesson_videos AS lv WHERE lv.subtopic_id = subtopics.id))
             RETURNING id, title, position, is_free, is_published, updated_at`,
            [lessonId]
        );

        if (result.rowCount === 1) {
            return res.json(result.rows[0]);
        }

        // Nothing changed: either there is no such lesson, or it isn't ready. Find out which, and say why.
        const lessonResult = await pool.query(
            `SELECT title, note_content,
                    (SELECT COUNT(*)::int FROM lesson_videos AS lv WHERE lv.subtopic_id = subtopics.id) AS video_count
             FROM subtopics
             WHERE id = $1`,
            [lessonId]
        );

        if (lessonResult.rowCount === 0) {
            return res.status(404).json({ error: 'Lesson not found.' });
        }

        const problems = findPublishProblems(lessonResult.rows[0]);

        res.status(409).json({
            error: problems.length > 0 ? 'This lesson is not ready to publish.' : 'The lesson changed while publishing. Please try again.',
            code: 'LESSON_NOT_READY',
            problems
        });
    }
    catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Hides a lesson from students again. Nothing is deleted, and students keep their progress on it.
app.post('/admin/lessons/:id/unpublish', async (req, res) => {
    const lessonId = parsePositiveInt(req.params.id);

    if (lessonId === null) {
        return res.status(400).json({ error: 'Invalid lesson id.' });
    }

    try {
        const result = await pool.query(
            `UPDATE subtopics
             SET is_published = FALSE,
                 updated_at = CASE WHEN is_published THEN NOW() ELSE updated_at END
             WHERE id = $1
             RETURNING id, title, position, is_free, is_published, updated_at`,
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

// Adds a video at the end of a lesson's list.
app.post('/admin/lessons/:id/videos', async (req, res) => {
    const lessonId = parsePositiveInt(req.params.id);

    if (lessonId === null) {
        return res.status(400).json({ error: 'Invalid lesson id.' });
    }

    const body = readBody(req);
    const link = cleanVideoLink(body.video_link);

    if (link === null) {
        return res.status(400).json({ error: 'A video link must be a web address starting with http:// or https://.' });
    }

    const title = cleanVideoTitle(body.title ?? null);

    if (!title.ok) {
        return res.status(400).json({ error: `A video title must be text, up to ${TITLE_MAX_LENGTH} characters.` });
    }

    try {
        const video = await withTransaction(async (client) => {
            await lockLesson(client, lessonId);

            const result = await client.query(
                `INSERT INTO lesson_videos (subtopic_id, title, video_link, position)
                 VALUES ($1, $2, $3, (SELECT COALESCE(MAX(position), 0) + 1 FROM lesson_videos WHERE subtopic_id = $1))
                 RETURNING id, title, video_link, position`,
                [lessonId, title.value, link]
            );

            await client.query('UPDATE subtopics SET updated_at = NOW() WHERE id = $1', [lessonId]);

            return result.rows[0];
        });

        res.status(201).json(video);
    }
    catch (err) {
        handleAdminError(res, err);
    }
});

// Changes a video's title or link. Only the fields sent are changed.
app.patch('/admin/videos/:id', async (req, res) => {
    const videoId = parsePositiveInt(req.params.id);

    if (videoId === null) {
        return res.status(400).json({ error: 'Invalid video id.' });
    }

    const body = readBody(req);
    const hasTitle = 'title' in body;
    const hasLink = 'video_link' in body;

    if (!hasTitle && !hasLink) {
        return res.status(400).json({ error: 'Send at least one of: title, video_link.' });
    }

    let newTitle;
    let newLink;

    if (hasTitle) {
        const cleaned = cleanVideoTitle(body.title);

        if (!cleaned.ok) {
            return res.status(400).json({ error: `A video title must be text, up to ${TITLE_MAX_LENGTH} characters.` });
        }

        newTitle = cleaned.value;
    }

    if (hasLink) {
        newLink = cleanVideoLink(body.video_link);

        if (newLink === null) {
            return res.status(400).json({ error: 'A video link must be a web address starting with http:// or https://.' });
        }
    }

    try {
        const video = await withTransaction(async (client) => {
            const found = await client.query('SELECT subtopic_id FROM lesson_videos WHERE id = $1', [videoId]);

            if (found.rowCount === 0) {
                throw new Refusal(404, { error: 'Video not found.' });
            }

            const lessonId = found.rows[0].subtopic_id;
            await lockLesson(client, lessonId);

            const result = await client.query(
                `UPDATE lesson_videos
                 SET title = CASE WHEN $2 THEN $3 ELSE title END,
                     video_link = CASE WHEN $4 THEN $5 ELSE video_link END
                 WHERE id = $1
                 RETURNING id, title, video_link, position`,
                [videoId, hasTitle, newTitle ?? null, hasLink, newLink ?? null]
            );

            await client.query('UPDATE subtopics SET updated_at = NOW() WHERE id = $1', [lessonId]);

            return result.rows[0];
        });

        res.json(video);
    }
    catch (err) {
        handleAdminError(res, err);
    }
});

// Moves a video one place up or down in its lesson. Sends back the lesson's videos in their new order.
app.post('/admin/videos/:id/move', async (req, res) => {
    const videoId = parsePositiveInt(req.params.id);

    if (videoId === null) {
        return res.status(400).json({ error: 'Invalid video id.' });
    }

    const direction = readBody(req).direction;

    if (direction !== 'up' && direction !== 'down') {
        return res.status(400).json({ error: 'direction must be "up" or "down".' });
    }

    try {
        const videos = await withTransaction(async (client) => {
            const found = await client.query('SELECT subtopic_id, position FROM lesson_videos WHERE id = $1', [videoId]);

            if (found.rowCount === 0) {
                throw new Refusal(404, { error: 'Video not found.' });
            }

            const { subtopic_id: lessonId, position } = found.rows[0];
            await lockLesson(client, lessonId);

            // The neighbour is the next video in that direction, so gaps left by removed videos don't matter.
            const neighbour = await client.query(
                direction === 'up'
                    ? 'SELECT id, position FROM lesson_videos WHERE subtopic_id = $1 AND position < $2 ORDER BY position DESC LIMIT 1'
                    : 'SELECT id, position FROM lesson_videos WHERE subtopic_id = $1 AND position > $2 ORDER BY position ASC LIMIT 1',
                [lessonId, position]
            );

            // Already first or last: nothing to move.
            if (neighbour.rowCount === 0) {
                return loadVideos(client, lessonId);
            }

            const other = neighbour.rows[0];

            // Two videos can't share a place, so the swap goes in three moves, via a temporary place.
            await client.query('UPDATE lesson_videos SET position = -1 WHERE id = $1', [videoId]);
            await client.query('UPDATE lesson_videos SET position = $2 WHERE id = $1', [other.id, position]);
            await client.query('UPDATE lesson_videos SET position = $2 WHERE id = $1', [videoId, other.position]);

            await client.query('UPDATE subtopics SET updated_at = NOW() WHERE id = $1', [lessonId]);

            return loadVideos(client, lessonId);
        });

        res.json(videos);
    }
    catch (err) {
        handleAdminError(res, err);
    }
});

// Removes a video. A live lesson can't lose its last piece of content, so that is refused.
app.delete('/admin/videos/:id', async (req, res) => {
    const videoId = parsePositiveInt(req.params.id);

    if (videoId === null) {
        return res.status(400).json({ error: 'Invalid video id.' });
    }

    try {
        const videos = await withTransaction(async (client) => {
            const found = await client.query('SELECT subtopic_id FROM lesson_videos WHERE id = $1', [videoId]);

            if (found.rowCount === 0) {
                throw new Refusal(404, { error: 'Video not found.' });
            }

            const lessonId = found.rows[0].subtopic_id;
            const lesson = await lockLesson(client, lessonId);
            const count = await client.query('SELECT COUNT(*)::int AS total FROM lesson_videos WHERE subtopic_id = $1', [lessonId]);

            // The rules are checked as they would be AFTER the removal.
            const wouldBeEmpty = findPublishProblems({
                title: lesson.title,
                note_content: lesson.note_content,
                video_count: count.rows[0].total - 1
            }).length > 0;

            if (lesson.is_published && wouldBeEmpty) {
                throw new Refusal(409, {
                    error: 'A live lesson needs notes or at least one video. Add notes, or unpublish the lesson first.',
                    code: 'LESSON_WOULD_BE_EMPTY'
                });
            }

            await client.query('DELETE FROM lesson_videos WHERE id = $1', [videoId]);
            await client.query('UPDATE subtopics SET updated_at = NOW() WHERE id = $1', [lessonId]);

            return loadVideos(client, lessonId);
        });

        res.json(videos);
    }
    catch (err) {
        handleAdminError(res, err);
    }
});

// What deleting a lesson would remove, so the page can say so before it asks.
app.get('/admin/lessons/:id/impact', async (req, res) => {
    const lessonId = parsePositiveInt(req.params.id);

    if (lessonId === null) {
        return res.status(400).json({ error: 'Invalid lesson id.' });
    }

    try {
        const result = await pool.query(
            `SELECT st.title, st.is_published,
                    (SELECT COUNT(*)::int FROM lesson_videos AS lv WHERE lv.subtopic_id = st.id) AS video_count,
                    (SELECT COUNT(*)::int FROM lesson_progress AS lp WHERE lp.subtopic_id = st.id) AS students_completed
             FROM subtopics AS st
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

// Deletes a lesson, its videos, and every student's completed mark for it. A live lesson must be unpublished first.
app.delete('/admin/lessons/:id', async (req, res) => {
    const lessonId = parsePositiveInt(req.params.id);

    if (lessonId === null) {
        return res.status(400).json({ error: 'Invalid lesson id.' });
    }

    try {
        const deleted = await withTransaction(async (client) => {
            const lesson = await lockLesson(client, lessonId);

            if (lesson.is_published) {
                throw new Refusal(409, {
                    error: 'This lesson is live. Unpublish it first, then delete it.',
                    code: 'LESSON_IS_LIVE'
                });
            }

            // Counted before the delete, so the answer can say what was removed.
            const counts = await client.query(
                `SELECT (SELECT COUNT(*)::int FROM lesson_videos WHERE subtopic_id = $1) AS videos,
                        (SELECT COUNT(*)::int FROM lesson_progress WHERE subtopic_id = $1) AS students_completed`,
                [lessonId]
            );

            await client.query('DELETE FROM subtopics WHERE id = $1', [lessonId]);

            return { title: lesson.title, ...counts.rows[0] };
        });

        res.json({ message: 'Lesson deleted.', deleted });
    }
    catch (err) {
        handleAdminError(res, err);
    }
});

// The whole structure of a subject for the content tree: sections, topics and lessons, drafts included.
app.get('/admin/subjects/:id/tree', async (req, res) => {
    const subjectId = parsePositiveInt(req.params.id);

    if (subjectId === null) {
        return res.status(400).json({ error: 'Invalid subject id.' });
    }

    try {
        const subjectResult = await pool.query(
            `SELECT s.id, s.name, s.description, s.unit, l.name AS level_name
             FROM subjects AS s
             JOIN levels AS l ON l.id = s.level_id
             WHERE s.id = $1`,
            [subjectId]
        );

        if (subjectResult.rowCount === 0) {
            return res.status(404).json({ error: 'Subject not found.' });
        }

        // The three lists don't depend on each other, so they run together.
        const [modulesResult, topicsResult, lessonsResult] = await Promise.all([
            pool.query('SELECT id, title, position FROM modules WHERE subject_id = $1 ORDER BY position', [subjectId]),
            pool.query(
                `SELECT t.id, t.module_id, t.title, t.position
                 FROM topics AS t
                 JOIN modules AS m ON m.id = t.module_id
                 WHERE m.subject_id = $1
                 ORDER BY t.position`,
                [subjectId]
            ),
            pool.query(
                `SELECT st.id, st.topic_id, st.title, st.position, st.is_free, st.is_published,
                        (COALESCE(btrim(st.note_content), '') <> '') AS has_notes,
                        (SELECT COUNT(*)::int FROM lesson_videos AS lv WHERE lv.subtopic_id = st.id) AS video_count
                 FROM subtopics AS st
                 JOIN topics AS t ON t.id = st.topic_id
                 JOIN modules AS m ON m.id = t.module_id
                 WHERE m.subject_id = $1
                 ORDER BY st.position`,
                [subjectId]
            )
        ]);

        const modules = modulesResult.rows.map((moduleRow) => ({
            ...moduleRow,
            topics: topicsResult.rows
                .filter((topicRow) => topicRow.module_id === moduleRow.id)
                .map((topicRow) => ({
                    ...topicRow,
                    lessons: lessonsResult.rows.filter((lessonRow) => lessonRow.topic_id === topicRow.id)
                }))
        }));

        res.json({ ...subjectResult.rows[0], modules });
    }
    catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Adds a section at the end of a subject. Students don't see it until it has something live in it (see the visibility step).
app.post('/admin/subjects/:id/modules', async (req, res) => {
    const subjectId = parsePositiveInt(req.params.id);

    if (subjectId === null) {
        return res.status(400).json({ error: 'Invalid subject id.' });
    }

    const title = cleanTitle(readBody(req).title);

    if (title === null) {
        return res.status(400).json({ error: `A title is required, up to ${TITLE_MAX_LENGTH} characters.` });
    }

    try {
        const result = await pool.query(
            `INSERT INTO modules (title, position, subject_id)
             VALUES ($1, (SELECT COALESCE(MAX(position), 0) + 1 FROM modules WHERE subject_id = $2), $2)
             RETURNING id, title, position`,
            [title, subjectId]
        );

        res.status(201).json(result.rows[0]);
    }
    catch (err) {
        // 23503 is a foreign key violation: the subject doesn't exist.
        if (err.code === '23503') {
            return res.status(404).json({ error: 'Subject not found.' });
        }

        // 23505 is a unique violation: another section took the same position at the same moment.
        if (err.code === '23505') {
            return res.status(409).json({ error: 'Another section was added at the same moment. Please try again.' });
        }

        console.error(err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Renames a section.
app.patch('/admin/modules/:id', async (req, res) => {
    const moduleId = parsePositiveInt(req.params.id);

    if (moduleId === null) {
        return res.status(400).json({ error: 'Invalid section id.' });
    }

    const title = cleanTitle(readBody(req).title);

    if (title === null) {
        return res.status(400).json({ error: `A title is required, up to ${TITLE_MAX_LENGTH} characters.` });
    }

    try {
        const result = await pool.query(
            'UPDATE modules SET title = $1 WHERE id = $2 RETURNING id, title, position',
            [title, moduleId]
        );

        if (result.rowCount === 0) {
            return res.status(404).json({ error: 'Section not found.' });
        }

        res.json(result.rows[0]);
    }
    catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Moves a section one place up or down in its subject. Sends back the subject's sections in their new order.
app.post('/admin/modules/:id/move', async (req, res) => {
    const moduleId = parsePositiveInt(req.params.id);

    if (moduleId === null) {
        return res.status(400).json({ error: 'Invalid section id.' });
    }

    const direction = readBody(req).direction;

    if (direction !== 'up' && direction !== 'down') {
        return res.status(400).json({ error: 'direction must be "up" or "down".' });
    }

    try {
        const modules = await withTransaction(async (client) => {
            const subjectId = await moveWithinParent(client, 'modules', moduleId, direction);
            const result = await client.query(
                'SELECT id, title, position FROM modules WHERE subject_id = $1 ORDER BY position',
                [subjectId]
            );

            return result.rows;
        });

        res.json(modules);
    }
    catch (err) {
        handleAdminError(res, err);
    }
});

// What deleting a section would remove, so the page can say so before it asks.
app.get('/admin/modules/:id/impact', async (req, res) => {
    const moduleId = parsePositiveInt(req.params.id);

    if (moduleId === null) {
        return res.status(400).json({ error: 'Invalid section id.' });
    }

    try {
        const result = await pool.query(
            `SELECT m.title,
                    (SELECT COUNT(*)::int FROM topics WHERE module_id = m.id) AS topic_count,
                    COUNT(st.id)::int AS lesson_count,
                    (COUNT(st.id) FILTER (WHERE st.is_published))::int AS live_lesson_count,
                    (SELECT COUNT(*)::int
                     FROM lesson_videos AS lv
                     JOIN subtopics AS s3 ON s3.id = lv.subtopic_id
                     JOIN topics AS t3 ON t3.id = s3.topic_id
                     WHERE t3.module_id = m.id) AS video_count,
                    (SELECT COUNT(DISTINCT lp.user_id)::int
                     FROM lesson_progress AS lp
                     JOIN subtopics AS s2 ON s2.id = lp.subtopic_id
                     JOIN topics AS t2 ON t2.id = s2.topic_id
                     WHERE t2.module_id = m.id) AS students_affected
             FROM modules AS m
             LEFT JOIN topics AS t ON t.module_id = m.id
             LEFT JOIN subtopics AS st ON st.topic_id = t.id
             WHERE m.id = $1
             GROUP BY m.id`,
            [moduleId]
        );

        if (result.rowCount === 0) {
            return res.status(404).json({ error: 'Section not found.' });
        }

        res.json(result.rows[0]);
    }
    catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Deletes a section with its topics, lessons, videos and every student's progress in it.
// A section containing a live lesson can't be deleted: unpublish those lessons first.
app.delete('/admin/modules/:id', async (req, res) => {
    const moduleId = parsePositiveInt(req.params.id);

    if (moduleId === null) {
        return res.status(400).json({ error: 'Invalid section id.' });
    }

    try {
        const deleted = await withTransaction(async (client) => {
            const moduleResult = await client.query('SELECT title FROM modules WHERE id = $1 FOR UPDATE', [moduleId]);

            if (moduleResult.rowCount === 0) {
                throw new Refusal(404, { error: 'Section not found.' });
            }

            // Every lesson in the section is locked while we decide, so none can be published in between.
            const lessons = await client.query(
                `SELECT st.id, st.is_published
                 FROM subtopics AS st
                 JOIN topics AS t ON t.id = st.topic_id
                 WHERE t.module_id = $1
                 FOR UPDATE OF st`,
                [moduleId]
            );

            const liveLessons = lessons.rows.filter((lessonRow) => lessonRow.is_published).length;

            if (liveLessons > 0) {
                throw new Refusal(409, {
                    error: `This section has ${liveLessons} live ${liveLessons === 1 ? 'lesson' : 'lessons'}. Unpublish ${liveLessons === 1 ? 'it' : 'them'} first, then delete the section.`,
                    code: 'CONTAINS_LIVE_LESSONS',
                    live_lessons: liveLessons
                });
            }

            // Counted before the delete, so the answer can say what was removed.
            const counts = await client.query(
                `SELECT (SELECT COUNT(*)::int FROM topics WHERE module_id = $1) AS topics,
                        (SELECT COUNT(*)::int
                         FROM lesson_videos AS lv
                         JOIN subtopics AS st ON st.id = lv.subtopic_id
                         JOIN topics AS t ON t.id = st.topic_id
                         WHERE t.module_id = $1) AS videos,
                        (SELECT COUNT(DISTINCT lp.user_id)::int
                         FROM lesson_progress AS lp
                         JOIN subtopics AS st ON st.id = lp.subtopic_id
                         JOIN topics AS t ON t.id = st.topic_id
                         WHERE t.module_id = $1) AS students_affected`,
                [moduleId]
            );

            await client.query('DELETE FROM modules WHERE id = $1', [moduleId]);

            return { title: moduleResult.rows[0].title, lessons: lessons.rowCount, ...counts.rows[0] };
        });

        res.json({ message: 'Section deleted.', deleted });
    }
    catch (err) {
        handleAdminError(res, err);
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

    if (err.type === 'entity.too.large') {
        return res.status(413).json({ error: 'That is too large to save.' });
    }

    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
});

app.listen(PORT, () => {
    console.log(`The server is running on port ${PORT}`);
});

