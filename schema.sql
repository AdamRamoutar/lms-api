-- The structure of the Carivo database.
-- A fresh database is built from this file. An existing database is changed with ALTER TABLE, and this file is updated to match.

CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    -- Who may do what. New accounts are always students, and admins are made by hand in the database.
    role VARCHAR(20) NOT NULL DEFAULT 'student',
    CONSTRAINT users_role_valid CHECK (role IN ('student', 'admin'))
);

CREATE TABLE levels (
    id SERIAL PRIMARY KEY,
    name VARCHAR(50) UNIQUE NOT NULL
);

-- A CAPE unit is its own subject row, so unit is empty for SEA and CSEC.
CREATE TABLE subjects (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    level_id INTEGER NOT NULL REFERENCES levels(id) ON DELETE CASCADE,
    unit INTEGER CHECK (unit IN (1, 2)),
    description TEXT,
    CONSTRAINT unique_subject_per_level UNIQUE (level_id, name)
);

-- A syllabus is divided into modules (CAPE) or sections (SEA and CSEC). The word shown is chosen in the frontend.
CREATE TABLE modules (
    id SERIAL PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    position INTEGER NOT NULL,
    subject_id INTEGER NOT NULL REFERENCES subjects(id) ON DELETE CASCADE,
    CONSTRAINT unique_module_position_per_subject UNIQUE (subject_id, position)
);

CREATE TABLE topics (
    id SERIAL PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    position INTEGER NOT NULL,
    module_id INTEGER NOT NULL REFERENCES modules(id) ON DELETE CASCADE,
    CONSTRAINT unique_topic_position_per_module UNIQUE (module_id, position)
);

-- A lesson. It can have notes, any number of videos (see lesson_videos), or both. Free lessons can be opened without a subscription.
-- A draft is only for admins, and a lesson is published when it is ready for students.
-- A published lesson must have notes or at least one video. Because that depends on another table, the API enforces it.
CREATE TABLE subtopics (
    id SERIAL PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    note_content TEXT,
    position INTEGER NOT NULL,
    is_free BOOLEAN NOT NULL DEFAULT FALSE,
    is_published BOOLEAN NOT NULL DEFAULT FALSE,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    topic_id INTEGER NOT NULL REFERENCES topics(id) ON DELETE CASCADE,
    CONSTRAINT unique_subtopic_position_per_topic UNIQUE (topic_id, position)
);

-- One row per video in a lesson. The title is optional, and position is the order within the lesson.
CREATE TABLE lesson_videos (
    id SERIAL PRIMARY KEY,
    subtopic_id INTEGER NOT NULL REFERENCES subtopics(id) ON DELETE CASCADE,
    title VARCHAR(255),
    video_link TEXT NOT NULL,
    position INTEGER NOT NULL,
    CONSTRAINT lesson_video_link_is_web_address CHECK (video_link ~* '^https?://'),
    CONSTRAINT unique_video_position_per_lesson UNIQUE (subtopic_id, position)
);

-- One row means a student has marked a lesson complete. Removing the row marks it incomplete again.
CREATE TABLE lesson_progress (
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    subtopic_id INTEGER NOT NULL REFERENCES subtopics(id) ON DELETE CASCADE,
    completed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, subtopic_id)
);

