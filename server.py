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
from datetime import datetime

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


def get_task(comp_id, tid):
    """Finds a task with a given category and score"""

    task = db.query("SELECT t.*, c.name cat_name FROM tasks t JOIN categories c on c.id = t.category JOIN competitions comp ON comp.id=t.competition WHERE t.id = :tid AND t.competition = :comp_id",
                    tid=tid, comp_id=comp_id)
    return list(task)[0]


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
    password = bleach.clean(request.form['password'], tags=[])
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

        user_found = db['users'].find_one(username=username)
        if user_found:
            return redirect('/error/already_registered')

        admin = False
        userCount = db['users'].count()

        #if no users, make first user admin
        if userCount == 0:
            admin = True

        new_user = dict(username=username,
            password=generate_password_hash(password), admin=admin)
        db['users'].insert(new_user)

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
    competition = db['competitions'].find_one(id=comp_id)
    if not competition:
        return redirect('/error/competition_not_found')

    running = is_running(comp_id)

    user = get_user()
    if not user:
        return redirect('/login')

    team = get_team(comp_id)
    if not team:
        return redirect('/competition/'+comp_id+'/team-register')

    if not competition['active'] and not user['admin']:
        return redirect('/error/competition_not_active')
    if not running and not user['admin']:
        return redirect('/competition/' + comp_id + '/countdown')


    categories = list(db['categories'].all())

    tasks = db.query("SELECT * FROM tasks t, task_competition tc WHERE t.id = tc.task_id AND tc.comp_id = :comp_id", comp_id=comp_id)
    tasks = sorted(list(tasks), key=lambda x: x['score'])

    render = render_template('competition.html', lang=lang,
                             user=user, competition=competition, categories=categories,
                             tasks=tasks, page=page, team=team, running=running,
                             **kwargs)
    return make_response(render)


@app.route('/competition/<comp_id>/')
@login_required
def competition(comp_id):
    return redirect('/competition/' + comp_id + '/stats')


@app.route('/competition/<comp_id>/stats', methods=['GET'])
@login_required
def competition_stats(comp_id):
    return competition_page(comp_id, 'competition-stats.html')


@app.route('/competition/<comp_id>/stats', methods=['POST'])
@login_required
def competition_stats_post(comp_id):
    user = get_user()
    competition = db['competitions'].find_one(id=comp_id)
    render = render_template('competition-stats.html', lang=lang, user=user, competition=competition)
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
        return redirect('/error/form')
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
    return competition_page(comp_id, 'competition-leaderboard.html')


@app.route('/competition/<comp_id>/leaderboard', methods=['POST'])
@login_required
def competition_leaderboard_post(comp_id):
    user = get_user()
    competition = db['competitions'].find_one(id=comp_id)
    render = render_template('competition-leaderboard.html', lang=lang, user=user, competition=competition)
    return render, 200


@app.route('/competition/<comp_id>/task/<task_id>', methods=['GET'])
@login_required
def competition_task(comp_id, task_id):
    task = db['tasks'].find_one(id=task_id)
    return competition_page(comp_id, 'competition-task.html', task=task)


@app.route('/competition/<comp_id>/task/<task_id>', methods=['POST'])
@login_required
def competition_task_post(comp_id, task_id):
    user = get_user()
    if get_team(comp_id) is None:
        return jsonify({}), 400

    task = db['tasks'].find_one(id=task_id)
    render = render_template('competition-task.html', lang=lang, task=task)
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

    render = render_template('competition-team.html', lang=lang, team=team)
    return make_response(render), 200


@app.route('/competition/<comp_id>/team-register', methods=['GET'])
@login_required
def competition_team_register(comp_id):
    competition = db['competitions'].find_one(id=comp_id)
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
        spectator=spectator
    )

    return teams.insert(team)


@app.route('/competition/<int:comp_id>/team-register', methods=['POST'])
@login_required
def competition_team_register_post(comp_id):
    secret = request.form['secret']

    competition = db['competitions'].find_one(id=comp_id)

    if secret != competition['secret'] and secret != competition['spectator_secret']:
        return redirect('/error/incorrect_secret')

    spectator = secret == competition['spectator_secret']

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









@app.route('/submit/<comp_id>/<tid>/<flag>')
@login_required
def submit(comp_id, tid, flag):
    """Handles the submission of flags"""

    user = get_user()

    task = get_task(comp_id, tid)
    flags = get_flags()
    task_done = task['id'] in flags

    result = {'success': False}
    if not task_done and task['flag'] == b64decode(flag):

        timestamp = int(time.time() * 1000)
        ip = request.remote_addr
        print "flag submitter ip: {}".format(ip)

        # Insert flag
        new_flag = dict(task_id=task['id'], user_id=session['user_id'],
            score=task["score"], timestamp=timestamp, ip=ip)
        db['flags'].insert(new_flag)

        result['success'] = True

    return jsonify(result)

@app.route('/scoreboard/<comp_id>/')
@login_required
def scoreboard(comp_id):
    """Displays the scoreboard"""

    user = get_user()
    scores = db.query("select u.username, ifnull(sum(f.score), 0) as score, max(timestamp) as last_submit, t.competition FROM users u left join flags f ON u.id = f.user_id LEFT JOIN tasks t ON f.task_id = t.id where u.isHidden = 0 AND t.competition = :comp_id group by u.username order by score desc, last_submit asc", comp_id=comp_id)

    scores = list(scores)

    # Render template
    render = render_template('frame.html', lang=lang, page='scoreboard.html',
        user=user, scores=scores)
    return make_response(render)


@app.route('/scoreboard.json')
def scoreboard_json():
    scores = db.query('''select u.username, ifnull(sum(f.score), 0) as score,
        max(timestamp) as last_submit from users u left join flags f
        on u.id = f.user_id where u.isHidden = 0 group by u.username
        order by score desc, last_submit asc''')

    scores = list(scores)

    return Response(json.dumps(scores), mimetype='application/json')



@app.route('/delete/<postID>', methods=['POST'])
@login_required
def deleteCompetitions(postID):

    user = get_user()
    if user["admin"]:
        competitions = db.query('''delete from competitions where id = ''' + postID)
        #flash('Lista deletada com sucesso')
    
    return redirect('/competitions')

@app.route('/competitions.json')
def competitions_json():
    competitions = db.query('''select * from competitions''')

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
