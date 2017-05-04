#!/bin/bash

#Create directory if it does not exist
mkdir -p static/files

sqlite3 ctf.db 'CREATE TABLE competitions (id INTEGER PRIMARY KEY, desc TEXT, date_start TEXT, date_end TEXT, active BOOLEAN, secret TEXT NOT NULL, spectator_secret TEXT NOT NULL, teams INTEGER, submissions INTEGER)';

sqlite3 ctf.db 'CREATE TABLE categories (id INTEGER PRIMARY KEY, name TEXT)';
sqlite3 ctf.db 'insert into categories (name) values ("Reverse Engineering")';
sqlite3 ctf.db 'insert into categories (name) values ("Web Exploitation")';
sqlite3 ctf.db 'insert into categories (name) values ("Forensics")';
sqlite3 ctf.db 'insert into categories (name) values ("Cryptography")';
sqlite3 ctf.db 'insert into categories (name) values ("Binary Exploitation")';
sqlite3 ctf.db 'insert into categories (name) values ("Miscellaneous")';

sqlite3 ctf.db 'CREATE TABLE tasks (id INTEGER PRIMARY KEY, name TEXT, desc TEXT, file TEXT, flag TEXT, category INT, FOREIGN KEY(category) REFERENCES categories(id) ON DELETE CASCADE);'
sqlite3 ctf.db 'CREATE TABLE task_competition (task_id INTEGER, comp_id INTEGER, score INTEGER, PRIMARY KEY (task_id, comp_id), FOREIGN KEY(task_id) REFERENCES tasks(id) ON DELETE CASCADE, FOREIGN KEY(comp_id) REFERENCES competitions(id) ON DELETE CASCADE);'
sqlite3 ctf.db 'CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT NOT NULL, email TEXT, admin BOOLEAN, password TEXT, shell_username TEXT)';
sqlite3 ctf.db 'CREATE TABLE teams (id INTEGER PRIMARY KEY, name TEXT NOT NULL, secret TEXT, comp_id INTEGER, spectator BOOLEAN, score INTEGER, timestamp BIGINT, FOREIGN KEY(comp_id) REFERENCES competitions(id) ON DELETE CASCADE)';
sqlite3 ctf.db 'CREATE TABLE team_player (team_id INTEGER, user_id INTEGER, PRIMARY KEY (team_id, user_id), FOREIGN KEY(team_id) REFERENCES teams(id) ON DELETE CASCADE, FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE)';
sqlite3 ctf.db 'CREATE TABLE flags (task_id INTEGER, user_id INTEGER, comp_id INTEGER, timestamp BIGINT, PRIMARY KEY (task_id, user_id, comp_id), FOREIGN KEY(task_id) REFERENCES tasks(id) ON DELETE CASCADE, FOREIGN KEY(comp_id) REFERENCES competitions(id) ON DELETE CASCADE, FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE);'
