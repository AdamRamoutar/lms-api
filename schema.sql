-- The structure of the Carivo database.
-- A fresh database is built from this file. An existing database is changed with ALTER TABLE, and this file is updated to match.

CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL
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

-- A lesson. It needs a video, notes, or both. Free lessons can be opened without a subscription.
CREATE TABLE subtopics (
    id SERIAL PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    video_link TEXT,
    note_content TEXT,
    position INTEGER NOT NULL,
    is_free BOOLEAN NOT NULL DEFAULT FALSE,
    topic_id INTEGER NOT NULL REFERENCES topics(id) ON DELETE CASCADE,
    CONSTRAINT unique_subtopic_position_per_topic UNIQUE (topic_id, position),
    CONSTRAINT subtopic_has_content CHECK (
        video_link IS NOT NULL OR note_content IS NOT NULL
    )
);