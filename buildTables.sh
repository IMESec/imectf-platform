#!/bin/bash

#Create directory if it does not exist
mkdir -p static/files

sqlite3 ctf.db 'CREATE TABLE competitions (id INTEGER PRIMARY KEY, desc TEXT, num_participants INTEGER, date_start TEXT, date_end TEXT, running INTEGER DEFAULT 0)';

sqlite3 ctf.db 'CREATE TABLE categories (id INTEGER PRIMARY KEY, name TEXT)';

sqlite3 ctf.db 'CREATE TABLE tasks (id INTEGER PRIMARY KEY, competition INT, name TEXT, desc TEXT, file TEXT, flag TEXT, score INT, category INT, FOREIGN KEY(category) REFERENCES categories(id) ON DELETE CASCADE);'

sqlite3 ctf.db 'CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT NOT NULL, email TEXT, isAdmin BOOLEAN, isHidden BOOLEAN, password TEXT)';

sqlite3 ctf.db 'CREATE TABLE flags (task_id INTEGER, user_id INTEGER, score INTEGER, timestamp BIGINT, ip TEXT, PRIMARY KEY (task_id, user_id), FOREIGN KEY(task_id) REFERENCES tasks(id) ON DELETE CASCADE, FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE);'
