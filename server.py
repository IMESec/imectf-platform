#!/usr/bin/env python

"""server.py -- the main flask server module"""

import dataset
import json
import random
import time
import hashlib
import os
import dateparser
import bleach
import re
import string
from datetime import datetime

from spur import LocalShell
from utils import create_user

from base64 import b64decode
from functools import wraps

from sqlalchemy import event
from sqlalchemy.engine import Engine
from sqlite3 import Connection as SQLite3Connection
from werkzeug.contrib.fixers import ProxyFix
from werkzeug.utils import secure_filename

from flask import Flask
from flask import jsonify
from flask import make_response
from flask import redirect
from flask import render_template
from flask import request
from flask import session
from flask import url_for
from flask import Response

app = Flask(__name__, static_folder='static', static_url_path='')

db = None
lang = None
config = None

descAllowedTags = bleach.ALLOWED_TAGS + ['br', 'pre']


@event.listens_for(Engine, "connect")
def _set_sqlite_pragma(dbapi_connection, connection_record):
    """ Enforces sqlite foreign key constrains """
    if isinstance(dbapi_connection, SQLite3Connection):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON;")
        cursor.close()


def sanitize_name(name):
    """
    Sanitize a given name such that it conforms to unix policy.
    Args:
        name: the name to sanitize.
    Returns:
        The sanitized form of name.
    """

    if len(name) == 0:
        raise Exception("Can not sanitize an empty field.")

    sanitized_name = re.sub(r"[^a-z0-9\+-]", "-", name.lower())

    if sanitized_name[0] in string.digits:
        sanitized_name = "p" + sanitized_name

    return sanitized_name


def login_required(f):
    """Ensures that an user is logged in"""

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect('/login')
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    """Ensures that an user is logged in"""

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect('/login')
        user = get_user()
        if not user or user["admin"] == False:
            return redirect(url_for('error', msg='admin_required'))
        return f(*args, **kwargs)
    return decorated_function


def get_user():
    """Looks up the current user in the database"""

    login = 'user_id' in session
    if login:
        return db['users'].find_one(id=session['user_id'])

    return None


def get_task(comp_id, task_id):
    """Finds a task with a given category and score"""

    task = list(db.query(
        '''
        SELECT * FROM tasks t JOIN task_competition tc
        ON t.id = tc.task_id
        WHERE t.id = :task_id AND tc.comp_id = :comp_id
        ''',
        task_id = task_id, comp_id = comp_id))

    if len(task) == 0:
        return None
    return task[0]


def get_team(comp_id):
    user = get_user()
    if not user:
        return None

    team = db.query('SELECT * FROM teams t JOIN team_player tp ON t.id = tp.team_id AND tp.user_id = :user_id AND t.comp_id = :comp_id LIMIT 1',
                    user_id=user['id'], comp_id=comp_id)
    team = list(team)

    if len(team) == 0:
        return None
    return team[0]


def get_flags():
    """Returns the flags of the current user"""

    flags = db.query('select f.task_id from flags f where f.user_id = :user_id',
                     user_id=session['user_id'])
    return [f['task_id'] for f in list(flags)]


def get_competition(comp_id):
    """Returns the current competition"""

    competition = db['competitions'].find_one(id=comp_id)
    return competition


def is_running(comp_id):
    """   """
    competition = get_competition(comp_id)
    if competition['active'] == False:
        return False

    startDate = datetime.strptime(competition['date_start'], "%Y-%m-%d %H:%M")
    endDate = datetime.strptime(competition['date_end'], "%Y-%m-%d %H:%M")

    if datetime.utcnow() > startDate and datetime.utcnow()< endDate:
        return True
        #db.query('UPDATE competitions SET running=1 WHERE id=:comp_id', comp_id=comp_id)


def get_time_remaining(comp_id):
    if not is_running(comp_id):
        return None

    competition = get_competition(comp_id)
    endDate = datetime.strptime(competition['date_end'], "%Y-%m-%d %H:%M")

    return (endDate - datetime.utcnow()).total_seconds()


def get_comp_score(comp_id):
    if not get_competition(comp_id):
        return 0

    score_comp = list(db.query("SELECT ifnull(total(score), 0) as score FROM task_competition WHERE comp_id=:comp_id", comp_id=comp_id))[0]
    return int(score_comp['score'])


'''
def recalculate_teams_score(comp_id):
    if not get_competition(comp_id):
        return 0
'''


def get_tasks_done(team_id, comp_id):
    flags = list(db.query(
        '''
        SELECT f.task_id
        FROM flags f JOIN team_player tp JOIN teams t
        ON f.user_id = tp.user_id AND tp.team_id = t.id
        WHERE f.comp_id = :comp_id AND t.id = :team_id
        ''',
        comp_id=comp_id, team_id=team_id
    ))
    flags = [x['task_id'] for x in flags]
    return flags


def get_team_scoreboard(comp_id, offset):
    scores = list(db.query(
        '''
        SELECT t.*,
        (
        SELECT count(*)+1
        FROM teams t2
        WHERE t2.id != t.id AND t2.spectator = 0 AND (t2.score > t.score OR (t2.score == t.score AND t2.timestamp <= t.timestamp))
        ) as rank
        FROM teams as t
        WHERE comp_id=:comp_id AND t.spectator = 0
        ORDER BY score DESC, timestamp ASC
        LIMIT 10
        OFFSET :offset
        ''',
        comp_id=comp_id, offset=offset
    ))

    return scores


def get_team_rank(comp_id, team_id):
    rank = list(db.query(
        '''
        SELECT
        (
        SELECT count(*)+1
        FROM teams t2
        WHERE t.id != t2.id AND t2.spectator = 0 AND (t2.score > t.score OR (t2.score == t.score AND t2.timestamp <= t.timestamp))
        ) as rank
        FROM teams t
        WHERE comp_id=:comp_id AND t.id = :team_id AND t.spectator = 0
        ''',
        comp_id=comp_id, team_id=team_id
    ))
    if len(rank) == 0:
        return 0
    return rank[0]['rank']


def get_total_users(comp_id):
    users = list(db.query(
        '''
        SELECT ifnull(count(*), 0) as count
        FROM users u JOIN team_player tp JOIN teams t
        ON u.id = tp.user_id AND tp.team_id = t.id
        WHERE t.spectator = 0 AND t.comp_id = :comp_id
        ''',
        comp_id=comp_id
    ))
    return users[0]['count']

@app.route('/')
def index():
    """Displays the main page"""

    user = get_user()

    # XXX
    return redirect('/login')

    # Render template
    render = render_template('main.html', lang=lang, user=user)
    return make_response(render)


@app.route('/error/<msg>')
def error(msg):
    """Displays an error message"""

    if msg in lang['error']:
        message = lang['error'][msg]
    else:
        message = lang['error']['unknown']

    user = get_user()

    render = render_template('error.html', lang=lang, message=message, user=user)
    return make_response(render)


def session_login(username):
    """Initializes the session with the current user's id"""
    user = db['users'].find_one(username=username)
    session['user_id'] = user['id']


@app.route('/login', methods = ['GET'])
def login_page():
    user = get_user()
    if user:
        return redirect('/competition/1')

    render = render_template('login.html', lang=lang)
    return make_response(render)


@app.route('/login', methods = ['POST'])
def login():
    from werkzeug.security import check_password_hash
    from werkzeug.security import generate_password_hash

    username = bleach.clean(request.form['username'], tags=[])
    password = request.form['password']
    if not username:
        return redirect('/error/empty_user')

    if 'login-button' in request.form:
        """Attempts to log the user in"""

        user = db['users'].find_one(username=username)
        if user is None:
            return redirect('/error/invalid_credentials')

        if check_password_hash(user['password'], password):
            session_login(username)
            #return redirect('/competitions')
            return redirect('/competition/1')

    if 'register-button' in request.form:
        """Attempts to register a new user"""

        shell_username = sanitize_name(username)

        user_found = db['users'].find_one(username=username)
        shell_found = db['users'].find_one(shell_username=shell_username)
        if user_found or shell_found:
            return redirect('/error/already_registered')

        admin = False
        userCount = db['users'].count()

        #if no users, make first user admin
        if userCount == 0:
            admin = True

        new_user = dict(username=username, password=generate_password_hash(password), admin=admin, shell_username=shell_username)
        db['users'].insert(new_user)

        create_user(shell_username, password)

        # Set up the user id for this session
        session_login(username)

        #return redirect('/competitions')
        return redirect('/competition/1')

    return redirect('/error/invalid_credentials')


@app.route('/logout')
@login_required
def logout():
    """Logs the current user out"""

    del session['user_id']
    return redirect('/')


@app.route('/competitions')
@login_required
def competitions():
    """Displays past competitions"""

    user = get_user()
    competitions = db.query('''select * from competitions''')

    competitions = list(competitions)

    # Render template
    render = render_template('competitions.html', lang=lang,
        user=user, competitions=competitions)
    return make_response(render)


@app.route('/competition/<comp_id>/edit', methods=['GET'])
@admin_required
def competition_edit(comp_id):
    competition = db['competitions'].find_one(id=comp_id)
    if not competition:
        return redirect('/error/competition_not_found')

    categories = list(db['categories'].all())

    tasks_comp = db.query("SELECT * FROM tasks t JOIN task_competition tc ON t.id = tc.task_id AND tc.comp_id = :comp_id", comp_id=comp_id)
    tasks_comp = list(tasks_comp)

    tasks = db.query("SELECT * FROM tasks WHERE id NOT IN (SELECT id FROM tasks t JOIN task_competition tc ON t.id = tc.task_id AND tc.comp_id = :comp_id)", comp_id=comp_id)
    tasks = list(tasks)

    render = render_template('competition-edit.html', lang=lang,
                             user=get_user(), tasks_comp=tasks_comp, tasks=tasks, competition=competition, categories=categories)
    return make_response(render)


@app.route('/competition/<comp_id>/addtask', methods=['POST'])
@admin_required
def competition_add_task(comp_id):
    try:
        comp_id = int(comp_id)
        task_id = int(request.form['task-id']);
        score = int(request.form['task-score']);
    except KeyError:
        return jsonify({'message': 'Internal error!'}), 400
    else:
        if not db['tasks'].find_one(id=task_id) or not db['competitions'].find_one(id=comp_id):
            return jsonify({'message': 'Invalid task or competition!'}), 400

        task_competition = db['task_competition']
        entry = dict(task_id=task_id, comp_id=comp_id, score=score)

        task_competition.insert(entry)

        task = list(db.query("SELECT * FROM tasks t JOIN task_competition tc ON t.id = :task_id AND tc.task_id = :task_id AND tc.comp_id = :comp_id LIMIT 1",
                        task_id = task_id, comp_id = comp_id))
        return jsonify(task[0]), 200


@app.route('/competition/<comp_id>/edittask', methods=['POST'])
@admin_required
def competition_edit_task(comp_id):
    try:
        comp_id = int(comp_id)
        task_id = int(request.form['task-id']);
        score = int(request.form['task-score']);
    except KeyError:
        return jsonify({'message': 'Internal error!'}), 400
    else:
        task_competition = db['task_competition']
        entry = task_competition.find_one(task_id = task_id, comp_id = comp_id)
        if not entry:
            return jsonify({'message': 'Not found'}), 400

        entry['score'] = score
        task_competition.update(entry, ['task_id', 'comp_id'])

        task = list(db.query("SELECT * FROM tasks t JOIN task_competition tc ON t.id = :task_id AND tc.task_id = :task_id AND tc.comp_id = :comp_id LIMIT 1",
                        task_id = task_id, comp_id = comp_id))
        return jsonify(task[0]), 200


@app.route('/competition/<comp_id>/removetask', methods=['POST'])
@admin_required
def competition_remove_task(comp_id):
    try:
        comp_id = int(comp_id)
        task_id = int(request.form['task-id']);
    except KeyError:
        return jsonify({'message': "Internal error!"}), 400
    else:
        db['task_competition'].delete(task_id = task_id, comp_id = comp_id)
        task = db['tasks'].find_one(id = task_id)
        return jsonify(task), 200


def competition_page(comp_id, page, **kwargs):
    competition = get_competition(comp_id)
    if not competition:
        return redirect('/error/competition_not_found')

    user = get_user()
    if not user:
        return redirect('/login')

    team = get_team(comp_id)
    if not team:
        return redirect('/competition/'+comp_id+'/team-register')

    running = is_running(comp_id)

    if not competition['active'] and not user['admin']:
        return redirect('/error/competition_not_active')
    if not running and not user['admin']:
        return redirect('/competition/' + comp_id + '/countdown')

    total_score = get_comp_score(comp_id)
    tasks_done = get_tasks_done(team['id'], comp_id)

    rank = get_team_rank(comp_id, team['id'])

    categories = list(db['categories'].all())

    tasks = db.query("SELECT * FROM tasks t, task_competition tc WHERE t.id = tc.task_id AND tc.comp_id = :comp_id", comp_id=comp_id)
    tasks = sorted(list(tasks), key=lambda x: x['score'])

    render = render_template('competition.html', lang=lang,
                             user=user, competition=competition, categories=categories,
                             tasks=tasks, page=page, team=team, running=running,
                             total_score=total_score, tasks_done=tasks_done,
                             rank=rank, **kwargs)
    return make_response(render)


@app.route('/competition/<comp_id>/')
@login_required
def competition(comp_id):
    return redirect('/competition/' + comp_id + '/stats')


@app.route('/competition/<comp_id>/stats', methods=['GET'])
@login_required
def competition_stats(comp_id):
    users = get_total_users(comp_id)

    return competition_page(comp_id, 'competition-stats.html', users=users)


@app.route('/competition/<comp_id>/stats', methods=['POST'])
@login_required
def competition_stats_post(comp_id):
    user = get_user()
    competition = get_competition(comp_id)
    users = get_total_users(comp_id)
    render = render_template('competition-stats.html', lang=lang, user=user, competition=competition, users=users)
    return render, 200


@app.route('/competition/<comp_id>/launch', methods=['GET'])
@admin_required
def competition_launch(comp_id):
    return competition_page(comp_id, 'competition-launch.html')


@app.route('/competition/<comp_id>/launch', methods=['POST'])
@admin_required
def competition_launch_post(comp_id):
    competition = db['competitions'].find_one(id=comp_id)
    render = render_template('competition-launch.html', lang=lang, competition=competition)
    return render, 200


@app.route('/competition/<comp_id>/launch/submit', methods=['POST'])
@admin_required
def competition_launch_submit(comp_id):
    """ Attempts to save competition and launch """
    competitions = db['competitions']
    competition = competitions.find_one(id=comp_id)
    if not competition:
        return redirect('/error/competition_not_found')

    try:
        name = bleach.clean(request.form['name'], tags=[])
        desc = bleach.clean(request.form['desc'], tags=descAllowedTags)
        date_start = request.form['date-start']
        date_end   = request.form['date-end']
    except KeyError:
        return jsonify({}), 400
    else:
        competition['name']       = name or competition['name']
        competition['desc']       = desc or competition['desc']
        competition['active']     = competition['active'] or ('launch-button' in request.form)
        competition['date_start'] = date_start or competition['date_start']
        competition['date_end']   = date_end   or competition['date_end']

        competitions.update(competition, ['id'])

        competition = competitions.find_one(id=comp_id)
        return jsonify(competition), 200

    return jsonify({}), 200


@app.route('/competition/<comp_id>/leaderboard', methods=['GET'])
@login_required
def competition_leaderboard(comp_id):
    return redirect('/competition/' + comp_id + '/leaderboard/0')


@app.route('/competition/<int:comp_id>/leaderboard/<int:offset>', methods=['GET'])
@login_required
def competition_leaderboard_offset(comp_id, offset):
    scores = get_team_scoreboard(comp_id, offset*10)
    return competition_page(comp_id, 'competition-leaderboard.html', scores=scores, offset=offset)


@app.route('/competition/<int:comp_id>/leaderboard/<int:offset>', methods=['POST'])
@login_required
def competition_leaderboard_offset_post(comp_id, offset):
    user = get_user()
    team = get_team(comp_id)
    if not team:
        return jsonify({}), 400

    competition = db['competitions'].find_one(id=comp_id)
    scores = get_team_scoreboard(comp_id, offset*10)
    render = render_template('competition-leaderboard.html', lang=lang, user=user,
                             competition=competition, scores=scores, team=team, offset=offset)
    return render, 200


@app.route('/competition/<comp_id>/task/<task_id>', methods=['GET'])
@login_required
def competition_task(comp_id, task_id):
    team = get_team(comp_id)
    if not team:
        return jsonify({}), 400

    task = db['tasks'].find_one(id=task_id)

    tasks_done = get_tasks_done(team['id'], comp_id)
    done = False
    if task['id'] in tasks_done:
        done = True
    return competition_page(comp_id, 'competition-task.html', task=task, done=done)


@app.route('/competition/<comp_id>/task/<task_id>', methods=['POST'])
@login_required
def competition_task_post(comp_id, task_id):
    user = get_user()
    team = get_team(comp_id)
    if not team:
        return jsonify({}), 400

    task = db['tasks'].find_one(id=task_id)
    competition = get_competition(comp_id)

    tasks_done = get_tasks_done(team['id'], comp_id)
    done = False
    if task['id'] in tasks_done:
        done = True

    render = render_template('competition-task.html', lang=lang,
                             task=task, competition=competition, done=done)
    return render, 200


@app.route('/competition/<comp_id>/team', methods=['GET'])
@login_required
def competition_team(comp_id):
    return competition_page(comp_id, 'competition-team.html')


@app.route('/competition/<comp_id>/team', methods=['POST'])
@login_required
def competition_team_post(comp_id):
    user = get_user()
    team = get_team(comp_id)
    if not team:
        return jsonify({}), 400
    total_score = get_comp_score(comp_id)
    rank = get_team_rank(comp_id, team['id'])
    competition = get_competition(comp_id)

    render = render_template('competition-team.html', lang=lang,
                             team=team, total_score=total_score, rank=rank,
                             competition=competition)
    return make_response(render), 200


@app.route('/competition/<comp_id>/team-register', methods=['GET'])
@login_required
def competition_team_register(comp_id):
    competition = get_competition(comp_id)
    if not competition:
        return redirect('/error/competition_not_found')

    user = get_user()
    team = get_team(comp_id)
    if team:
        return redirect('/competition/'+comp_id+'/team')

    render = render_template('competition-team-register.html', lang=lang, user=user, competition=competition)
    return make_response(render), 200


def create_team(name, comp_id, secret, spectator):
    teams = db['teams']

    team = dict(
        name=name,
        comp_id=comp_id,
        secret=secret,
        spectator=spectator,
        score=0,
        timestamp = 0
    )

    return teams.insert(team)


@app.route('/competition/<int:comp_id>/team-register', methods=['POST'])
@login_required
def competition_team_register_post(comp_id):
    secret = request.form['secret']

    competition = get_competition(comp_id)
    if not competition:
        return redirect('/error/competition_not_found')

    if secret != competition['secret'] and secret != competition['spectator_secret']:
        return redirect('/error/incorrect_secret')

    spectator = (secret == competition['spectator_secret'])

    if 'register-button' in request.form:
        try:
            name = bleach.clean(request.form['team-name'], tags=[])
        except KeyError:
            return redirect('/error/form')
        else:
            if len(name) == 0:
                return redirect('/error/form')

            team_id = create_team(
                name,
                comp_id,
                hashlib.md5(str(datetime.utcnow())).hexdigest(),
                spectator
            )

            team_player = db['team_player']
            team_player.insert(dict(team_id=team_id, user_id=session['user_id']))

            if not spectator:
                competition = get_competition(comp_id)
                competition['teams'] += 1

            db['competitions'].update(competition, ['id'])

            #return redirect('/competitions')
            return redirect('/competition/1')

    if 'join-button' in request.form:
        try:
            team_secret = bleach.clean(request.form['team-secret'], tags=[])
        except KeyError:
            return redirect('/error/form')
        else:
            team = db.query("SELECT * FROM teams WHERE secret = :team_secret AND comp_id = :comp_id", team_secret=team_secret, comp_id=comp_id)
            team = list(team)

            if len(team) == 0:
                return redirect('/error/wrong_hash')
            else:
                team=team[0]
                team_players = db.query("SELECT * FROM team_player WHERE team_id = :team_id", team_id=team['id'])
                team_players = list(team_players)
                if len(team_players) == 3:
                    return redirect('/error/too_many_members')
                else:
                    team_playersDB = db['team_player']
                    team_playersDB.insert(dict(team_id=team['id'], user_id= session['user_id']))

            #return redirect('/competitions')
            return redirect('/competition/1')


@app.route('/competition/<comp_id>/countdown')
@login_required
def competition_countdown(comp_id):
    user = get_user()
    competition = get_competition(comp_id)

    if not competition:
        return redirect('/error/competition_not_found')
    if not competition['active']:
        return redirect('/error/competition_not_active')

    date_start = datetime.strptime(competition['date_start'], '%Y-%m-%d %H:%M')
    diff = (date_start - datetime.utcnow()).total_seconds()

    if diff <= 0:
        return redirect('/competition/' + comp_id)

    render = render_template('competition-countdown.html', lang=lang,
                             user=user, competition=competition, diff=diff)
    return make_response(render), 200





'''
@app.route('/addcat/', methods=['GET'])
@admin_required
def addcat():
    user = get_user()
    render = render_template('frame.html', lang=lang, user=user, page='addcat.html')
    return make_response(render)

@app.route('/addcat/', methods=['POST'])
@admin_required
def addcatsubmit():
    try:
        name = bleach.clean(request.form['name'], tags=[])
    except KeyError:
        return redirect('/error/form')
    else:
        categories = db['categories']
        categories.insert(dict(name=name))

        return redirect('/competitions')
'''








# TODO change this to modal in /competitions
@app.route('/competition/new', methods=['GET'])
@admin_required
def competition_new():
    user = get_user()

    render = render_template('competition-new.html', lang=lang, user=user)
    return make_response(render)

@app.route('/competition/new', methods=['POST'])
@admin_required
def competition_new_submit():
    try:
        name = bleach.clean(request.form['name'], tags=descAllowedTags)
        desc = bleach.clean(request.form['desc'], tags=descAllowedTags)
    except KeyError:
        return redirect('/error/form')
    else:
        competitions = db['competitions']
        competition = dict(
            name=name,
            desc=desc,
            active=0,
            secret = hashlib.md5('secret'+str(datetime.utcnow())).hexdigest(),
            spectator_secret = hashlib.md5('spectator'+str(datetime.utcnow())).hexdigest(),
            teams=0
        )

        competitions.insert(competition)

        return redirect('/competitions')


def generate_filename(file):
    filename, ext = os.path.splitext(file.filename)
    #hash current time for file name
    filename = secure_filename(filename) + '_' + hashlib.md5(str(datetime.utcnow())).hexdigest()

    #if upload has extension, append to filename
    if ext:
        filename = filename + ext
    return filename


def store_file(file):
    filename = generate_filename(file)
    file.save(os.path.join("static/files/", filename))
    return filename


def delete_file(filename):
    os.remove(os.path.join("static/files/", filename))



@app.route('/tasks/', methods=['GET'])
@admin_required
def tasks():
    categories = list(db['categories'].all())

    tasks = db.query('SELECT * FROM tasks')
    tasks = list(tasks)

    user = get_user()
    render = render_template('tasks.html', lang=lang, user=user,
            categories=categories, tasks=tasks)
    return make_response(render)


@app.route('/task/add', methods=['POST'])
@admin_required
def task_add():
    try:
        name = bleach.clean(request.form['task-name'], tags=[])
        desc = bleach.clean(request.form['task-desc'], tags=descAllowedTags)
        category = int(request.form['task-category'])
        hint = request.form['task-hint']
        flag = request.form['task-flag']
        if not flag:
            return jsonify({'message': 'No flag set'}), 400
    except KeyError:
        return jsonify({'message': 'Form incorrect filled'}), 400
    else:
        tasks = db['tasks']
        task = dict(
                name=name,
                desc=desc,
                category=category,
                hint=hint,
                flag=flag)
        file = request.files['task-file']

        if file:
            task['file'] = store_file(file)
            #tasks.update(task, ['id'])

        task_id = tasks.insert(task)

        task = tasks.find_one(id=task_id)
        return jsonify(task), 200


@app.route('/task/edit', methods=['POST'])
@admin_required
def task_edit():
    try:
        tid = request.form['task-id']
        name = bleach.clean(request.form['task-name'], tags=[])
        desc = bleach.clean(request.form['task-desc'], tags=descAllowedTags)
        category = int(request.form['task-category'])
        hint = request.form['task-hint']
        flag = request.form['task-flag']
        if not flag:
            return jsonify({ 'message': 'No flag set' }), 400
    except KeyError:
        return jsonify({ 'message': 'Form incorrect filled' }), 400
    else:
        tasks = db['tasks']
        task = tasks.find_one(id=tid)
        task['name'] = name
        task['desc'] = desc
        task['category'] = category
        task['hint'] = hint
        task['flag'] = flag

        file = request.files['task-file']

        if file:
            filename = store_file(file)

            #remove old file
            if task['file']:
                delete_file(task['file'])

            task["file"] = filename

        tasks.update(task, ['id'])
        task = tasks.find_one(name = task["name"], flag = task["flag"])
        return jsonify(task), 200


@app.route('/task/delete', methods=['POST'])
@admin_required
def task_delete():
    task_id = int(request.form['task-id'])

    task = db['tasks'].find_one(id=task_id)

    if task is None:
        return jsonify({ 'message': 'Task not found!' }), 400

    if task['file']:
        delete_file(task['file'])

    db['tasks'].delete(id=task_id)
    return jsonify({}), 200


@app.route('/task/<task_id>', methods=['GET', 'POST'])
@admin_required
def task_get(task_id):
    task = db["tasks"].find_one(id=task_id)
    if not task:
        return jsonify({ 'message': 'Not found' }), 400
    return jsonify(task)


@app.route('/task_competition/<cid>-<tid>', methods=['GET', 'POST'])
@admin_required
def task_competition_get(cid, tid):
    task = list(db.query('SELECT * FROM tasks t JOIN task_competition tc ON t.id = tc.task_id AND t.id = :task_id AND tc.comp_id = :comp_id LIMIT 1',
                         task_id = tid, comp_id = cid));
    if len(task) == 0:
        return jsonify({ 'message': 'Not found' }), 400
    return jsonify(task[0]), 200


@app.route('/competition/<int:comp_id>/task/<int:task_id>/submit', methods=['POST'])
@login_required
def submit(comp_id, task_id):
    """Handles the submission of flags"""
    competition = get_competition(comp_id)
    if not competition:
        return jsonify({}), 400

    task = get_task(comp_id, task_id)
    if not task:
        return jsonify({}), 400
    task_id = task['id']

    team = get_team(comp_id)
    if not team:
        return jsonify({}), 400
    team_id = team['id']

    # Verify if flag is correct
    flag = request.form['flag']
    if task['flag'] != flag:
        return jsonify({ 'success': False }), 200

    user = get_user()
    user_id = user["id"]
    timestamp = int(time.time() * 1000)

    # Verify if player didn't solved this task yet
    user_solved = list(db.query('SELECT * FROM flags WHERE task_id = :task_id AND user_id = :user_id AND comp_id = :comp_id',
                           task_id = task_id, user_id = user_id, comp_id = comp_id))

    # if team have not solved before, update team score
    team_solved = list(db.query(
        '''SELECT * FROM
        flags f JOIN team_player tp JOIN teams t
        ON
        f.user_id = tp.user_id AND tp.team_id = t.id
        WHERE
        f.task_id = :task_id AND f.comp_id = :comp_id AND t.id = :team_id''',
        task_id=task_id, user_id=user_id, comp_id=comp_id, team_id=team_id))

    if len(user_solved) == 0:
        # if not, add new flag to db
        flag = dict(
            task_id = task_id,
            user_id = user_id,
            comp_id = comp_id,
            timestamp = timestamp
        )
        db['flags'].insert(flag)

    if len(team_solved) == 0:
        task_competition = db['task_competition'].find_one(task_id = task_id, comp_id = comp_id)
        team['score'] += task_competition['score']
        team['timestamp'] = timestamp
        db['teams'].update(team, ['id'])

    return jsonify(
        {
            'success': True,
            'score': team['score'],
            'total_score': get_comp_score(comp_id),
            'rank': get_team_rank(comp_id, team_id),
            'total_teams': competition['teams']
        }
    )


'''
@app.route('/competitions.json')
def competitions_json():
    competitions = db.query("""select * from competitions""")

    competitions = list(competitions)

    return Response(json.dumps(competitions), competitions=competitions, mimetype='application/json')

@app.route('/about')
@login_required
def about():
    """Displays the about menu"""

    user = get_user()

    # Render template
    render = render_template('frame.html', lang=lang, page='about.html',
        user=user)
    return make_response(render)
'''

""" Filters """
@app.template_filter('date')
def format_date(date):
    return datetime.strptime(date, '%Y-%m-%d %H:%M').strftime('%d/%m/%Y %H:%M')


"""Initializes the database and sets up the language"""

# Load config
config_str = open('config.json', 'rb').read()
config = json.loads(config_str)

# Load environment config
app.secret_key = os.getenv('SECRETKEY', 'changeme')
if app.secret_key == 'changeme':
    print 'Configure a SECRETKEY envvar!'

# Load language
lang_str = open(config['language_file'], 'rb').read()
lang = json.loads(lang_str)

# Only a single language is supported for now
lang = lang[config['language']]

# Connect to database
db = dataset.connect(config['db'])

if config['isProxied']:
    app.wsgi_app = ProxyFix(app.wsgi_app)

if __name__ == '__main__':
    # Start web server
    app.run(host=config['host'], port=config['port'],
        debug=config['debug'], threaded=True, extra_files=['config.json', config['language_file']])
