#!/usr/bin/env python

"""server.py -- the main flask server module"""

import dataset
import json
import random
import time
import hashlib
import datetime
import os
import dateparser
import bleach

from base64 import b64decode
from functools import wraps

from sqlalchemy import event
from sqlalchemy.engine import Engine
from sqlite3 import Connection as SQLite3Connection
from werkzeug.contrib.fixers import ProxyFix

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

def login_required(f):
    """Ensures that an user is logged in"""

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('error', msg='login_required'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    """Ensures that an user is logged in"""

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('error', msg='login_required'))
        user = get_user()
        if user["isAdmin"] == False:
            return redirect(url_for('error', msg='admin_required'))
        return f(*args, **kwargs)
    return decorated_function

def get_user():
    """Looks up the current user in the database"""

    login = 'user_id' in session
    if login:
        return db['users'].find_one(id=session['user_id'])

    return None

def get_task(tid):
    """Finds a task with a given category and score"""

    task = db.query("SELECT t.*, c.name cat_name FROM tasks t JOIN categories c on c.id = t.category WHERE t.id = :tid",
            tid=tid)

    return list(task)[0]

def get_flags():
    """Returns the flags of the current user"""

    flags = db.query('''select f.task_id from flags f
        where f.user_id = :user_id''',
        user_id=session['user_id'])
    return [f['task_id'] for f in list(flags)]

@app.route('/error/<msg>')
def error(msg):
    """Displays an error message"""

    if msg in lang['error']:
        message = lang['error'][msg]
    else:
        message = lang['error']['unknown']

    user = get_user()

    render = render_template('frame.html', lang=lang, page='error.html',
        message=message, user=user)
    return make_response(render)

def session_login(username):
    """Initializes the session with the current user's id"""
    user = db['users'].find_one(username=username)
    session['user_id'] = user['id']

@event.listens_for(Engine, "connect")
def _set_sqlite_pragma(dbapi_connection, connection_record):
    """ Enforces sqlite foreign key constrains """
    if isinstance(dbapi_connection, SQLite3Connection):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON;")
        cursor.close()

@app.route('/login', methods = ['POST'])
def login():
    """Attempts to log the user in"""

    from werkzeug.security import check_password_hash

    username = request.form['user']
    password = request.form['password']

    user = db['users'].find_one(username=username)
    if datetime.datetime.today() > config['endTime'] and user['isAdmin']==False:
        return redirect('/error/finished')
    if user is None:
        return redirect('/error/invalid_credentials')

    if check_password_hash(user['password'], password):
        session_login(username)
        return redirect('/tasks')

    return redirect('/error/invalid_credentials')

@app.route('/register')
def register():
    """Displays the register form"""

    userCount = db['users'].count()
    if datetime.datetime.today() < config['startTime'] and userCount != 0:
        return redirect('/error/not_started')

    if datetime.datetime.today() > config['endTime'] and userCount != 0:
        return redirect('/error/finished')

    # Render template
    render = render_template('frame.html', lang=lang,
        page='register.html', login=False)
    return make_response(render)

@app.route('/register/submit', methods = ['POST'])
def register_submit():
    """Attempts to register a new user"""

    from werkzeug.security import generate_password_hash

    username = request.form['user']
    #email = request.form['email']
    password = request.form['password']

    if not username:
        return redirect('/error/empty_user')

    user_found = db['users'].find_one(username=username)
    if user_found:
        return redirect('/error/already_registered')

    isAdmin = False
    isHidden = False
    userCount = db['users'].count()

    #if no users, make first user admin
    if userCount == 0:
        isAdmin = True
        isHidden = True
    elif datetime.datetime.today() < config['startTime']:
        return redirect('/error/not_started')


    new_user = dict(username=username, #email=email,
        password=generate_password_hash(password), isAdmin=isAdmin,
        isHidden=isHidden)
    db['users'].insert(new_user)

    # Set up the user id for this session
    session_login(username)

    return redirect('/tasks')

@app.route('/tasks')
@login_required
def tasks():
    """Displays all the tasks in a grid"""

    user = get_user()
    userCount = db['users'].count()

    categories = db['categories']
    catCount = categories.count()

    flags = db['flags']

    tasks = db.query("SELECT * FROM tasks ORDER BY category, score");

    tasks = list(tasks)

    grid = []

    rowCount = 0
    currentCat = 0
    currentCatCount = 0

    if len(tasks) == 0:
        row = [None] * catCount
        grid.append(row)

    for task in tasks:
        cat = task["category"] - 1

        while currentCatCount + 1 >= rowCount:
            row = [None] * catCount
            grid.append(row)
            rowCount += 1

        if currentCat != cat:
            if user['isAdmin']:
                endTask = { "end": True, "category": currentCat }
                grid[currentCatCount][currentCat] = endTask
            currentCat = cat
            currentCatCount = 0


        percentComplete = (float(flags.count(task_id=task['id'])) / userCount) * 100

        #hax for bad css (if 100, nothing will show)
        if percentComplete == 100:
            percentComplete = 99.99

        task['percentComplete'] = percentComplete

        isComplete = bool(flags.count(task_id=task['id'], user_id=user['id']))

        task['isComplete'] = isComplete

        grid[currentCatCount][cat] = task
        currentCatCount += 1

    #add the final endTask element
    if user['isAdmin']:
        if len(tasks) > 0:
            endTask = { "end": True, "category": currentCat }
            grid[currentCatCount][currentCat] = endTask

        #if any None in first row, add end task
        for i, t in enumerate(grid[0]):
            if t is None:
                endTask = { "end": True, "category": i }
                grid[0][i] = endTask


    # Render template
    render = render_template('frame.html', lang=lang, page='tasks.html',
        user=user, categories=categories, grid=grid)
    return make_response(render)

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
        return redirect('/tasks')

@app.route('/addtask/<cat>/', methods=['GET'])
@admin_required
def addtask(cat):
    category = db.query('SELECT * FROM categories LIMIT 1 OFFSET :cat', cat=cat)
    category = list(category)
    category = category[0]

    user = get_user()

    render = render_template('frame.html', lang=lang, user=user,
            cat_name=category['name'], cat_id=category['id'], page='addtask.html')
    return make_response(render)

@app.route('/addtask/<cat>/', methods=['POST'])
@admin_required
def addtasksubmit(cat):
    try:
        name = bleach.clean(request.form['name'], tags=[])
        desc = bleach.clean(request.form['desc'], tags=descAllowedTags)
        category = int(request.form['category'])
        score = int(request.form['score'])
        hint = request.form['hint']
        flag = request.form['flag']
    except KeyError:
        return redirect('/error/form')

    else:
        tasks = db['tasks']
        task = dict(
                name=name,
                desc=desc,
                category=category,
                score=score,
                hint=hint,
                flag=flag)
        file = request.files['file']

        if file:
            filename, ext = os.path.splitext(file.filename)
            #hash current time for file name
            filename = hashlib.md5(str(datetime.datetime.utcnow())).hexdigest()
            #if upload has extension, append to filename
            if ext:
                filename = filename + ext
            file.save(os.path.join("static/files/", filename))
            task["file"] = filename

        tasks.insert(task)
        return redirect('/tasks')

@app.route('/tasks/<tid>/edit', methods=['GET'])
@admin_required
def edittask(tid):
    user = get_user()

    task = db["tasks"].find_one(id=tid);
    category = db["categories"].find_one(id=task['category'])

    render = render_template('frame.html', lang=lang, user=user,
            cat_name=category['name'], cat_id=category['id'],
            page='edittask.html', task=task)
    return make_response(render)

@app.route('/tasks/<tid>/edit', methods=['POST'])
@admin_required
def edittasksubmit(tid):
    try:
        name = bleach.clean(request.form['name'], tags=[])
        desc = bleach.clean(request.form['desc'], tags=descAllowedTags)
        category = int(request.form['category'])
        score = int(request.form['score'])
        hint = request.form['hint']
        flag = request.form['flag']
    except KeyError:
        return redirect('/error/form')

    else:
        tasks = db['tasks']
        task = tasks.find_one(id=tid)
        task['id']=tid
        task['name']=name
        task['desc']=desc
        task['category']=category
        task['hint']=hint
        task['score']=score

        #only replace flag if value specified
        if flag:
            task['flag']=flag

        file = request.files['file']

        if file:
            filename, ext = os.path.splitext(file.filename)
            #hash current time for file name
            filename = hashlib.md5(str(datetime.datetime.utcnow())).hexdigest()
            #if upload has extension, append to filename
            if ext:
                filename = filename + ext
            file.save(os.path.join("static/files/", filename))

            #remove old file
            if task['file']:
                os.remove(os.path.join("static/files/", task['file']))

            task["file"] = filename

        tasks.update(task, ['id'])
        return redirect('/tasks')

@app.route('/tasks/<tid>/delete', methods=['GET'])
@admin_required
def deletetask(tid):
    tasks = db['tasks']
    task = tasks.find_one(id=tid)

    user = get_user()
    render = render_template('frame.html', lang=lang, user=user, page='deletetask.html', task=task)
    return make_response(render)

@app.route('/tasks/<tid>/delete', methods=['POST'])
@admin_required
def deletetasksubmit(tid):
    db['tasks'].delete(id=tid)
    return redirect('/tasks')

@app.route('/tasks/<tid>/')
@login_required
def task(tid):
    """Displays a task with a given category and score"""

    user = get_user()

    task = get_task(tid)
    if not task:
        return redirect('/error/task_not_found')

    flags = get_flags()
    task_done = task['id'] in flags

    solutions = db['flags'].find(task_id=task['id'])
    solutions = len(list(solutions))

    # Render template
    render = render_template('frame.html', lang=lang, page='task.html',
        task_done=task_done, login=login, solutions=solutions,
        user=user, category=task["cat_name"], task=task, score=task["score"])
    return make_response(render)

@app.route('/submit/<tid>/<flag>')
@login_required
def submit(tid, flag):
    """Handles the submission of flags"""

    user = get_user()

    task = get_task(tid)
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

@app.route('/scoreboard')
@login_required
def scoreboard():
    """Displays the scoreboard"""

    user = get_user()
    scores = db.query('''select u.username, ifnull(sum(f.score), 0) as score,
        max(timestamp) as last_submit from users u left join flags f
        on u.id = f.user_id where u.isHidden = 0 group by u.username
        order by score desc, last_submit asc''')

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

@app.route('/about')
@login_required
def about():
    """Displays the about menu"""

    user = get_user()

    # Render template
    render = render_template('frame.html', lang=lang, page='about.html',
        user=user)
    return make_response(render)


@app.route('/chat')
@login_required
def chat():
    """Displays the IRC chat"""

    # Render template
    render = render_template('frame.html', lang=lang, page='chat.html')
    return make_response(render)


@app.route('/logout')
@login_required
def logout():
    """Logs the current user out"""

    del session['user_id']
    return redirect('/')

@app.route('/')
def index():
    """Displays the main page"""

    user = get_user()

    # Render template
    render = render_template('frame.html', lang=lang,
        page='main.html', user=user)
    return make_response(render)

"""Initializes the database and sets up the language"""

# Load config
config_str = open('config.json', 'rb').read()
config = json.loads(config_str)

app.secret_key = config['secret_key']

# Convert start date to python object
if config['startTime']:
    config['startTime'] = dateparser.parse(config['startTime'])
else:
    config['startTime'] = datetime.datetime.min

if config['endTime']:
    config['endTime'] = dateparser.parse(config['endTime'])
else:
    config['endTime'] = datetime.datetime.min


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
        debug=config['debug'], threaded=True)

